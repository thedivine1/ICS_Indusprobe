"""
indus_probe.advisory.matcher
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Deterministic, evidence-based CVE applicability matching engine.

Matching logic:
  For each (asset, applicability_rule) pair:
    1. Check identification quality — if too weak, return INSUFFICIENT_IDENTITY.
    2. Vendor match — if vendor does not match, skip rule.
    3. Product match — keyword matching against model_raw / device_hint / software_name.
       If no keyword matches, return NO_APPLICABLE_RULE_FOUND.
    4. Version evaluation — if product matches:
       a. If all_versions=True, return AFFECTED_PER_ADVISORY.
       b. If installed version is unknown: PRODUCT_MATCH_VERSION_UNKNOWN.
       c. If version string is present but unparseable: PRODUCT_MATCH_VERSION_AMBIGUOUS.
       d. If version is in affected range: AFFECTED_PER_ADVISORY.
       e. If version is outside affected range: NOT_AFFECTED_PER_ADVISORY.

Three-valued logic:
  TRUE  → AFFECTED_PER_ADVISORY
  FALSE → NOT_AFFECTED_PER_ADVISORY  (for THIS advisory only)
  UNKNOWN → PRODUCT_MATCH_VERSION_UNKNOWN / PRODUCT_MATCH_VERSION_AMBIGUOUS

Epistemic guarantees:
  - A FALSE or NO_APPLICABLE_RULE_FOUND result for one advisory is NEVER
    propagated as a general "clean" statement.
  - A PRODUCT_MATCH_VERSION_UNKNOWN result is ALWAYS retained as a candidate
    — it is never silently dropped.
"""

from __future__ import annotations

import datetime
import json
import logging
import sqlite3
from typing import Any, Dict, List, Optional

from indus_probe.advisory.models import AssetFact, MatchResult, MatchState
from indus_probe.advisory.version_engine import (
    VersionComparisonError,
    is_version_in_affected_range,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Vendor normalisation helpers
# ---------------------------------------------------------------------------

_VENDOR_ALIASES: Dict[str, str] = {
    "schneider": "SCHNEIDER",
    "schneider electric": "SCHNEIDER",
    "se": "SCHNEIDER",
    "rockwell": "ROCKWELL",
    "rockwell automation": "ROCKWELL",
    "allen-bradley": "ROCKWELL",
    "allen bradley": "ROCKWELL",
}


def _normalise_vendor(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    return _VENDOR_ALIASES.get(raw.strip().lower())


# ---------------------------------------------------------------------------
# Product match
# ---------------------------------------------------------------------------

def _product_matches(asset: AssetFact, keywords: List[str]) -> bool:
    """
    Return True if any keyword appears in the asset's model, device_hint,
    software_name, or software_version fields.
    Case-insensitive substring match.
    """
    search_fields = [
        (asset.model_raw or "").lower(),
        (asset.device_hint or "").lower(),
        (asset.software_name or "").lower(),
        (asset.firmware_version_raw or "").lower(),
    ]
    for kw in keywords:
        kw_lower = kw.lower()
        for field_val in search_fields:
            if kw_lower in field_val:
                return True
    return False


# ---------------------------------------------------------------------------
# Core match function
# ---------------------------------------------------------------------------

def evaluate_asset_against_rule(
    asset: AssetFact,
    rule_row: sqlite3.Row,
) -> MatchResult:
    """
    Evaluate one asset against one applicability rule row (from DB).

    Returns a MatchResult with a categorical MatchState and human-readable reasoning.
    """
    advisory_id = rule_row["advisory_id"]
    cve_id = ""       # populated from advisory_cves at call site
    product_name = rule_row["product_name"]
    version_scheme = rule_row["version_scheme"]
    version_lt = rule_row["version_lt"]
    version_lte = rule_row["version_lte"]
    version_gte = rule_row["version_gte"]
    all_versions = bool(rule_row["all_versions"])

    try:
        keywords = json.loads(rule_row["match_keywords"] or "[]")
    except json.JSONDecodeError:
        keywords = []

    rule_vendor = rule_row["vendor"]

    # --- Step 1: Identification quality gate ---
    if not asset.model_raw and not asset.device_hint and not asset.software_name:
        return MatchResult(
            asset_ip=asset.ip,
            advisory_id=advisory_id,
            cve_id=cve_id,
            state=MatchState.INSUFFICIENT_IDENTITY,
            reasoning=(
                "Asset {} has no model, device_hint, or software_name. "
                "OUI-only identification is insufficient for product-level matching. "
                "Advisory {} cannot be evaluated.".format(asset.ip, advisory_id)
            ),
            missing_evidence="Model number, device hint, or software package name",
        )

    # --- Step 2: Vendor match ---
    asset_vendor_code = _normalise_vendor(asset.vendor)
    if asset_vendor_code is None or asset_vendor_code != rule_vendor:
        # Return None to signal caller to skip this rule (no match row emitted)
        return None  # type: ignore[return-value]

    # --- Step 3: Product keyword match ---
    if not _product_matches(asset, keywords):
        return MatchResult(
            asset_ip=asset.ip,
            advisory_id=advisory_id,
            cve_id=cve_id,
            state=MatchState.NO_APPLICABLE_RULE_FOUND,
            reasoning=(
                "Vendor matches ({}) but no product keyword matched for rule product "
                "'{}'.  Asset model/hint: {!r} / {!r}.  "
                "IMPORTANT: This result applies only to advisory {}.  "
                "It is not a clean bill of health.".format(
                    rule_vendor, product_name,
                    asset.model_raw, asset.device_hint,
                    advisory_id,
                )
            ),
            missing_evidence=None,
        )

    # --- Step 4: Version evaluation ---

    # 4a: Advisory affects all versions
    if all_versions:
        installed = asset.firmware_version_raw or asset.software_version_raw
        return MatchResult(
            asset_ip=asset.ip,
            advisory_id=advisory_id,
            cve_id=cve_id,
            state=MatchState.AFFECTED_PER_ADVISORY,
            reasoning=(
                "Product matched: {}.  Advisory {} states all versions are affected. "
                "Installed firmware/software: {!r} (version check not applicable).".format(
                    product_name, advisory_id, installed
                )
            ),
            missing_evidence=None,
        )

    # Determine the best available version string
    installed_version = asset.firmware_version_raw or asset.software_version_raw

    # 4b: Version is completely unknown
    if not installed_version:
        return MatchResult(
            asset_ip=asset.ip,
            advisory_id=advisory_id,
            cve_id=cve_id,
            state=MatchState.PRODUCT_MATCH_VERSION_UNKNOWN,
            reasoning=(
                "Product keyword matched ({} → {}).  "
                "Firmware/software version not observed in passive capture.  "
                "Advisory {} affects versions {}.  "
                "Cannot confirm affected or not-affected without version evidence.  "
                "Retain as candidate; version walkdown required.".format(
                    asset.model_raw or asset.device_hint,
                    product_name,
                    advisory_id,
                    version_lt or version_lte or "see advisory",
                )
            ),
            missing_evidence=(
                "Firmware or software version for {} ({}).  "
                "Affected range: {} per advisory {}.".format(
                    asset.model_raw or asset.device_hint,
                    asset.ip,
                    version_lt or version_lte or "unspecified",
                    advisory_id,
                )
            ),
        )

    # 4c / 4d / 4e: Version is present — attempt comparison
    # Only attempt if version bounds exist
    if version_lt is None and version_lte is None:
        return MatchResult(
            asset_ip=asset.ip,
            advisory_id=advisory_id,
            cve_id=cve_id,
            state=MatchState.PRODUCT_MATCH_VERSION_UNKNOWN,
            reasoning=(
                "Product matched but advisory rule has no parseable version bound. "
                "Installed: {!r}. Rule product: {}. Advisory: {}.".format(
                    installed_version, product_name, advisory_id
                )
            ),
            missing_evidence="Structured version boundary in advisory rule",
        )

    result = is_version_in_affected_range(
        installed_raw=installed_version,
        version_scheme=version_scheme,
        version_lt=version_lt,
        version_lte=version_lte,
        version_gte=version_gte,
    )

    if result is None:
        # Version string present but comparison returned UNKNOWN
        return MatchResult(
            asset_ip=asset.ip,
            advisory_id=advisory_id,
            cve_id=cve_id,
            state=MatchState.PRODUCT_MATCH_VERSION_AMBIGUOUS,
            reasoning=(
                "Product matched ({} → {}).  "
                "Installed version {!r} could not be compared against boundary {!r} "
                "using scheme {}.  Retain as candidate pending analyst review.".format(
                    asset.model_raw or asset.device_hint, product_name,
                    installed_version, version_lt or version_lte,
                    version_scheme,
                )
            ),
            missing_evidence=(
                "Interpretable version for {} using {} scheme".format(
                    asset.ip, version_scheme
                )
            ),
        )

    if result:
        return MatchResult(
            asset_ip=asset.ip,
            advisory_id=advisory_id,
            cve_id=cve_id,
            state=MatchState.AFFECTED_PER_ADVISORY,
            reasoning=(
                "Product matched ({} → {}).  "
                "Installed version {!r} is within the affected range "
                "(boundary: {} {!r}, scheme: {}).  "
                "Advisory: {}.".format(
                    asset.model_raw or asset.device_hint, product_name,
                    installed_version,
                    "< " if version_lt else "<= ",
                    version_lt or version_lte,
                    version_scheme, advisory_id,
                )
            ),
        )

    return MatchResult(
        asset_ip=asset.ip,
        advisory_id=advisory_id,
        cve_id=cve_id,
        state=MatchState.NOT_AFFECTED_PER_ADVISORY,
        reasoning=(
            "Product matched ({} → {}).  "
            "Installed version {!r} is OUTSIDE the affected range "
            "(boundary: {} {!r}, scheme: {}).  "
            "Advisory: {}.  "
            "NOTE: This result applies ONLY to advisory {}.  "
            "It is not a clean bill of health or general security assurance.".format(
                asset.model_raw or asset.device_hint, product_name,
                installed_version,
                "< " if version_lt else "<= ",
                version_lt or version_lte,
                version_scheme, advisory_id, advisory_id,
            )
        ),
    )


# ---------------------------------------------------------------------------
# Batch matcher
# ---------------------------------------------------------------------------

def run_match(
    assets: List[AssetFact],
    conn: sqlite3.Connection,
) -> List[MatchResult]:
    """
    Run all advisory rules against all assets.

    Returns a flat list of MatchResult objects.
    Rules are loaded from the DB; assets are provided as AssetFact instances.
    Rules for which the vendor does not match any asset are skipped silently.
    """
    from indus_probe.advisory.db import get_all_rules

    rules = get_all_rules(conn)
    if not rules:
        logger.warning("No applicability rules found in DB. Ingest advisories first.")
        return []

    # Pre-build: advisory_id → list of CVE IDs
    cve_map: Dict[str, List[str]] = {}
    rows = conn.execute("SELECT advisory_id, cve_id FROM advisory_cves").fetchall()
    for row in rows:
        cve_map.setdefault(row["advisory_id"], []).append(row["cve_id"])

    results: List[MatchResult] = []

    for asset in assets:
        vendor_code = _normalise_vendor(asset.vendor)

        for rule in rules:
            result = evaluate_asset_against_rule(asset, rule)
            if result is None:
                # Vendor mismatch — skip silently
                continue

            # Attach CVE IDs from advisory_cves
            advisory_cves = cve_map.get(result.advisory_id, [])
            if advisory_cves:
                result.cve_id = advisory_cves[0]  # Primary CVE
                # Emit separate results for additional CVEs
                results.append(result)
                for extra_cve in advisory_cves[1:]:
                    extra = MatchResult(
                        asset_ip=result.asset_ip,
                        advisory_id=result.advisory_id,
                        cve_id=extra_cve,
                        state=result.state,
                        reasoning=result.reasoning,
                        missing_evidence=result.missing_evidence,
                        advisory_title=result.advisory_title,
                        vendor=result.vendor,
                        affected_range_text=result.affected_range_text,
                        mitigation_note=result.mitigation_note,
                    )
                    results.append(extra)
            else:
                results.append(result)

    logger.info(
        "Match complete: %d assets × %d rules → %d results",
        len(assets), len(rules), len(results),
    )
    return results

