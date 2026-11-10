"""
indus_probe.advisory.adapter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Backward-compatible adapter for the existing IndusProbe report pipeline.

Preserves the original `lookup_cves_for_assets(assets)` interface so that
`indus_probe/report.py` continues to work unchanged during the transition
to the new advisory intelligence module.

Adapter strategy:
  1. Convert existing asset dicts (from capture.py) to AssetFact objects.
  2. Run the evidence-based matcher against the loaded advisory DB.
  3. Convert MatchResult objects back to the dict format expected by report.py.

If the advisory DB does not exist or is empty, falls back to the legacy
cve_lookup module transparently, with a warning.

PRODUCTION CODE IS NOT MODIFIED. This adapter is a new file only.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Default DB location (can be overridden via INDUSPROBE_ADVISORY_DB env var)
_DEFAULT_DB_PATH = str(Path(__file__).parent.parent.parent / "data" / "advisories.db")


def lookup_cves_for_assets(assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Evidence-based CVE lookup — drop-in replacement for the legacy function.

    Args:
        assets: List of asset dicts as produced by capture.py Asset.to_dict()

    Returns:
        List of advisory dicts compatible with the report.py template.
        Each dict includes:
          cve_id, vendor, identified_product, affected_range, official_title,
          cisa_advisory, vendor_advisory, source_url, mitigation, mechanism,
          applicability, installed_version, affected_assets, identity_basis

    Fallback:
        If advisory DB is missing or empty, falls back to legacy cve_lookup.py
        and logs a warning.
    """
    db_path = os.environ.get("INDUSPROBE_ADVISORY_DB", _DEFAULT_DB_PATH)

    if not Path(db_path).exists():
        logger.warning(
            "Advisory DB not found at %s. Falling back to legacy cve_lookup. "
            "Run: indus-advisory ingest ... to populate the DB first.",
            db_path,
        )
        return _legacy_fallback(assets)

    try:
        from indus_probe.advisory.db import open_db, get_all_advisories
        conn = open_db(db_path)
        advisories_in_db = get_all_advisories(conn)
        if not advisories_in_db:
            logger.warning(
                "Advisory DB exists but contains no advisories. "
                "Falling back to legacy cve_lookup."
            )
            conn.close()
            return _legacy_fallback(assets)

        from indus_probe.advisory.models import AssetFact, IdentificationBasis
        from indus_probe.advisory.matcher import run_match

        asset_facts = [_dict_to_asset_fact(a) for a in assets]
        results = run_match(asset_facts, conn)
        conn.close()
        return _results_to_report_dicts(results)

    except Exception as exc:
        logger.error(
            "Advisory matcher raised an unexpected error: %s. "
            "Falling back to legacy cve_lookup.", exc, exc_info=True
        )
        return _legacy_fallback(assets)


# ---------------------------------------------------------------------------
# Conversion helpers
# ---------------------------------------------------------------------------

def _dict_to_asset_fact(d: Dict[str, Any]) -> "AssetFact":
    from indus_probe.advisory.models import AssetFact, IdentificationBasis

    # Map legacy 'identity_source' field to IdentificationBasis
    legacy_basis = d.get("identity_source", "")
    if "manifest" in legacy_basis.lower():
        basis = IdentificationBasis.LAB_MANIFEST
    elif "register" in legacy_basis.lower():
        basis = IdentificationBasis.CLIENT_REGISTER
    elif "parsed" in legacy_basis.lower():
        basis = IdentificationBasis.PARSED_IDENTITY
    else:
        basis = IdentificationBasis.OUI_INFERENCE

    device_hint = d.get("device_hint", "")

    return AssetFact(
        ip=d.get("ip", ""),
        mac=d.get("mac"),
        vendor=d.get("vendor"),
        # Legacy assets store everything in device_hint; use it as model_raw too
        model_raw=device_hint,
        firmware_version_raw=d.get("firmware_version"),
        software_name=None,
        software_version_raw=None,
        identification_basis=basis,
        provenance_note=legacy_basis or None,
        device_hint=device_hint,
    )


def _results_to_report_dicts(results: List[Any]) -> List[Dict[str, Any]]:
    """Convert MatchResult objects to the dict format expected by report.py."""
    # Group by (advisory_id, cve_id) to consolidate affected assets into one row
    advisory_map: Dict[str, Dict[str, Any]] = {}

    for r in results:
        key = "{}::{}".format(r.advisory_id, r.cve_id)
        if key not in advisory_map:
            advisory_map[key] = {
                "cve_id": r.cve_id,
                "vendor": r.vendor or "",
                "identified_product": r.advisory_title or r.advisory_id,
                "affected_range": r.affected_range_text or "See advisory",
                "official_title": r.advisory_title or r.cve_id,
                "cisa_advisory": r.advisory_id,
                "vendor_advisory": r.advisory_id,
                "source_url": "",
                "mitigation": r.mitigation_note or "",
                "mechanism": "",
                "applicability": _state_to_applicability(r.state.value),
                "installed_version": "Unknown (passive capture)",
                "affected_assets": [],
                "identity_basis": "Advisory intelligence module",
            }
        advisory_map[key]["affected_assets"].append(
            "`{}` ({})".format(r.asset_ip, r.state.value)
        )

    return list(advisory_map.values())


def _state_to_applicability(state: str) -> str:
    _MAP = {
        "AFFECTED_PER_ADVISORY": "CONFIRMED CANDIDATE — Firmware/version confirms applicability",
        "NOT_AFFECTED_PER_ADVISORY": "NOT APPLICABLE — Installed version outside affected range",
        "PRODUCT_MATCH_VERSION_UNKNOWN": "CANDIDATE — Product matched; version verification required",
        "PRODUCT_MATCH_VERSION_AMBIGUOUS": "CANDIDATE — Version present but cannot be parsed; analyst review required",
        "PRODUCT_EXCLUDED_BY_ADVISORY": "NOT APPLICABLE — Product excluded by advisory scope",
        "NO_APPLICABLE_RULE_FOUND": "NOT APPLICABLE — No matching advisory rule for this product",
        "INSUFFICIENT_IDENTITY": "CANNOT EVALUATE — Insufficient asset identification data",
        "EVALUATION_ERROR": "EVALUATION ERROR — Internal matcher error; review logs",
    }
    return _MAP.get(state, state)


# ---------------------------------------------------------------------------
# Legacy fallback
# ---------------------------------------------------------------------------

def _legacy_fallback(assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Delegate to the original hardcoded cve_lookup module."""
    try:
        from indus_probe.cve_lookup import lookup_cves_for_assets as _legacy
        return _legacy(assets)
    except ImportError:
        logger.error("Legacy cve_lookup also unavailable. Returning empty CVE list.")
        return []

