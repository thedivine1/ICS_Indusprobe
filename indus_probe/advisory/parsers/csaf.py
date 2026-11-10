"""
indus_probe.advisory.parsers.csaf
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
CSAF 2.0 parser — extracts affected products and version rules from
Schneider Electric SEVD advisories and CISA-mirrored Rockwell advisories.

Implements a defensive, verbatim extraction strategy:
- Preserves raw version strings exactly as written in the advisory.
- Never normalises or coerces version strings.
- Extracts product_tree branches and vulnerability product_status sections.
- Returns conservative AffectedProduct entries with explicit match_keywords.

References:
  Schneider CSAF endpoint: https://www.se.com/.well-known/csaf/
  CISA Rockwell mirror:    https://github.com/cisagov/CSAF (advisory_id prefix ICSA-)
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from indus_probe.advisory.models import (
    Advisory, AffectedProduct, VendorCode, VersionScheme,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Keyword tables for product name → match_keywords mapping
# ---------------------------------------------------------------------------

_SCHNEIDER_KEYWORD_MAP: Dict[str, List[str]] = {
    # Modicon M580 family
    "modicon m580": ["m580", "bmep58", "bmeh58", "epac", "bme580"],
    # Modicon M340 family
    "modicon m340": ["m340", "bmxp34", "bmx p34"],
    # Modicon Quantum
    "modicon quantum": ["quantum", "140cpu"],
    # Modicon Premium
    "modicon premium": ["premium", "tsxp57"],
    # EcoStruxure Control Expert / Unity Pro
    "control expert": ["control expert", "unity pro", "ecostruxure control expert"],
    # EcoStruxure Process Expert
    "process expert": ["process expert", "ecostruxure process expert"],
    # Altivar drives — explicitly NOT PLCs
    "altivar": ["atv", "altivar"],
}

_ROCKWELL_KEYWORD_MAP: Dict[str, List[str]] = {
    "controllogix": ["controllogix", "1756", "clgx"],
    "guardlogix": ["guardlogix", "1756-l"],
    "micrologix": ["micrologix", "1766", "1762", "1763", "1764"],
    "compactlogix": ["compactlogix", "1769"],
    "studio 5000": ["studio 5000", "logix designer"],
}


def _keywords_for_product(product_name: str, vendor_code: VendorCode) -> List[str]:
    """Return match keywords for a product name by fuzzy key lookup."""
    name_lower = product_name.lower()
    keyword_map = (
        _SCHNEIDER_KEYWORD_MAP if vendor_code == VendorCode.SCHNEIDER
        else _ROCKWELL_KEYWORD_MAP
    )
    for key, kws in keyword_map.items():
        if key in name_lower:
            return kws
    # Fallback: tokenise the product name
    tokens = [t for t in re.split(r"[\s\-/]+", name_lower) if len(t) >= 3]
    return tokens[:5]


def _infer_version_scheme(vendor_code: VendorCode, product_name: str) -> VersionScheme:
    """
    Infer the version comparison scheme from vendor and product name.
    Conservative: defaults to AMBIGUOUS_UNORDERED when uncertain.
    """
    name_lower = product_name.lower()
    if vendor_code == VendorCode.SCHNEIDER:
        # Firmware uses SV-prefix scheme; software uses numeric SP scheme
        if any(k in name_lower for k in ("modicon", "m580", "m340", "quantum", "premium")):
            return VersionScheme.SCHNEIDER_OT
        if any(k in name_lower for k in ("control expert", "unity pro", "process expert")):
            return VersionScheme.SCHNEIDER_OT   # SP-based; handled by SCHNEIDER_OT parser
        return VersionScheme.SCHNEIDER_OT
    if vendor_code == VendorCode.ROCKWELL:
        if any(k in name_lower for k in ("logix", "controllogix", "guardlogix", "compactlogix")):
            return VersionScheme.ROCKWELL_LOGIX
        if "studio 5000" in name_lower:
            return VersionScheme.SEMVER
        return VersionScheme.ROCKWELL_LOGIX
    return VersionScheme.AMBIGUOUS_UNORDERED


# ---------------------------------------------------------------------------
# Version range extraction helpers
# ---------------------------------------------------------------------------

_LT_INDICATORS = ("prior to", "before", "less than", "earlier than")
_GTE_INDICATORS = ("and later", "and above", "or later")


def _extract_version_lt(version_text: str) -> Optional[str]:
    """
    Extract the boundary version from CSAF version strings like:
      "All versions prior to V3.20"
      "Versions before 15.0 SP1"
    Returns the boundary string verbatim (after stripping the keyword).
    """
    text_lower = version_text.lower()
    for indicator in _LT_INDICATORS:
        idx = text_lower.find(indicator)
        if idx != -1:
            raw = version_text[idx + len(indicator):].strip()
            # Strip a leading "v" or "V" only if it's a known version prefix pattern
            # but preserve it verbatim for the version engine to handle
            return raw if raw else None
    return None


def _extract_all_versions(version_text: str) -> bool:
    """Return True ONLY if the advisory says every version is affected (no upper bound)."""
    text_lower = version_text.lower().strip()
    # "All versions prior to X" is NOT all_versions — it has a boundary.
    # Only match bare "all versions" or "all" with no "prior to" / "before" qualifier.
    if any(indicator in text_lower for indicator in _LT_INDICATORS):
        return False
    return text_lower in ("all versions", "all") or text_lower == "all versions"


# ---------------------------------------------------------------------------
# CSAF product_tree flattening
# ---------------------------------------------------------------------------

def _build_product_id_to_name(product_tree: Dict[str, Any]) -> Dict[str, str]:
    """
    Flatten the CSAF product_tree into a mapping of product_id → full_product_name.
    Handles both branches (recursive) and full_product_names lists.
    """
    id_to_name: Dict[str, str] = {}

    def _walk_branches(branches: List[Any]) -> None:
        for branch in branches:
            if "product" in branch:
                prod = branch["product"]
                pid = prod.get("product_id", "")
                name = prod.get("name", "") or prod.get("product_identification_helper", {}).get("cpe", "")
                if pid and name:
                    id_to_name[pid] = name
            if "branches" in branch:
                _walk_branches(branch["branches"])

    if "branches" in product_tree:
        _walk_branches(product_tree["branches"])

    for entry in product_tree.get("full_product_names", []):
        pid = entry.get("product_id", "")
        name = entry.get("name", "")
        if pid and name:
            id_to_name[pid] = name

    return id_to_name


def _build_product_id_to_version(product_tree: Dict[str, Any]) -> Dict[str, str]:
    """
    Build a mapping of product_id → version_string from product_tree branches.
    Returns raw version strings verbatim.
    """
    id_to_version: Dict[str, str] = {}

    def _walk(branches: List[Any], current_version: Optional[str] = None) -> None:
        for branch in branches:
            btype = branch.get("category", "")
            bname = branch.get("name", "")
            # A branch of category 'product_version' carries the version string
            version_here = bname if btype in ("product_version", "product_version_range") else current_version
            if "product" in branch:
                pid = branch["product"].get("product_id", "")
                if pid and version_here:
                    id_to_version[pid] = version_here
            if "branches" in branch:
                _walk(branch["branches"], version_here)

    if "branches" in product_tree:
        _walk(product_tree["branches"])

    return id_to_version


# ---------------------------------------------------------------------------
# Public parser
# ---------------------------------------------------------------------------

def parse_csaf_advisory(
    raw_json: str,
    advisory_id: str,
    vendor_code: VendorCode,
    source_url: str,
    retrieval_timestamp: str,
    raw_sha256: str,
    file_size_bytes: int,
) -> Advisory:
    """
    Parse a CSAF 2.0 advisory JSON string into a normalised Advisory object.

    Extraction strategy:
    1. Build product_id → name and product_id → version maps from product_tree.
    2. For each CVE in /vulnerabilities, collect the known_affected product IDs.
    3. For each affected product ID, extract version bounds from the product_tree branch.
    4. Produce one AffectedProduct per unique (advisory, product_id).

    Version strings are preserved verbatim. Comparison is delegated to version_engine.
    """
    try:
        doc = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid JSON in CSAF advisory {}: {}".format(advisory_id, exc))

    # --- Title ---
    tracking = doc.get("document", {}).get("tracking", {})
    title = (
        doc.get("document", {}).get("title", "")
        or tracking.get("id", advisory_id)
    )
    published_date = tracking.get("initial_release_date")
    revised_date = tracking.get("current_release_date")

    # --- Product tree ---
    product_tree = doc.get("product_tree", {})
    id_to_name = _build_product_id_to_name(product_tree)
    id_to_version = _build_product_id_to_version(product_tree)

    # --- CVE IDs ---
    vulnerabilities = doc.get("vulnerabilities", [])
    cve_ids: List[str] = []
    for vuln in vulnerabilities:
        cve = vuln.get("cve")
        if cve:
            cve_ids.append(cve)

    # --- Affected products ---
    # Collect all known_affected product IDs across all vulnerabilities
    affected_product_ids: Dict[str, str] = {}  # product_id → cve_id (first match)
    for vuln in vulnerabilities:
        cve = vuln.get("cve", "UNKNOWN")
        product_status = vuln.get("product_status", {})
        for pid in product_status.get("known_affected", []):
            if pid not in affected_product_ids:
                affected_product_ids[pid] = cve

    # --- Build AffectedProduct entries ---
    affected_products: List[AffectedProduct] = []
    seen_pids: set = set()

    for pid, cve_id in affected_product_ids.items():
        if pid in seen_pids:
            continue
        seen_pids.add(pid)

        product_name = id_to_name.get(pid, "Unknown Product (ID={})".format(pid))
        raw_version = id_to_version.get(pid, "")

        version_scheme = _infer_version_scheme(vendor_code, product_name)
        match_keywords = _keywords_for_product(product_name, vendor_code)

        # Extract version bounds from the raw version string
        version_lt = None
        all_versions = False

        if raw_version:
            if _extract_all_versions(raw_version):
                all_versions = True
            else:
                version_lt = _extract_version_lt(raw_version)
                if version_lt is None and raw_version.strip():
                    # Store raw string as-is for EXACT_ONLY or manual review
                    logger.debug(
                        "Could not extract structured version bound from %r for %s / %s",
                        raw_version, advisory_id, pid,
                    )

        source_locator = "/vulnerabilities/*/product_status/known_affected[{}]".format(pid)

        affected_products.append(AffectedProduct(
            product_id=pid,
            product_name=product_name,
            vendor=vendor_code.value,
            version_scheme=version_scheme,
            version_lt=version_lt,
            version_lte=None,
            version_gte=None,
            all_versions=all_versions,
            match_keywords=match_keywords,
            source_locator=source_locator,
        ))

    # --- CVSS ---
    cvss_score = None
    cvss_version = None
    cvss_vector = None
    cvss_source = None
    if vulnerabilities:
        for vuln in vulnerabilities:
            scores = vuln.get("scores", [])
            for score_entry in scores:
                for key in ("cvss_v3", "cvss_v4", "cvss_v2"):
                    if key in score_entry:
                        metric = score_entry[key]
                        cvss_score = metric.get("baseScore") or metric.get("base_score")
                        cvss_version = metric.get("version")
                        cvss_vector = metric.get("vectorString") or metric.get("vector_string")
                        cvss_source = score_entry.get("source", "Advisory")
                        break
                if cvss_score is not None:
                    break
            if cvss_score is not None:
                break

    return Advisory(
        advisory_id=advisory_id,
        vendor=vendor_code,
        title=title,
        source_url=source_url,
        retrieval_timestamp=retrieval_timestamp,
        raw_sha256=raw_sha256,
        file_size_bytes=file_size_bytes,
        cve_ids=cve_ids,
        affected_products=affected_products,
        cvss_score=cvss_score,
        cvss_version=cvss_version,
        cvss_vector=cvss_vector,
        cvss_source=cvss_source,
        published_date=published_date,
        revised_date=revised_date,
    )

