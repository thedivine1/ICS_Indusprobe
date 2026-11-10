"""
indus_probe.advisory.parsers.cve_json
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
CVE JSON 5.1 parser (CVEProject/cvelistV5 format).

Purpose: supplement advisory product data with authoritative CVE metadata
(CNA, description, published date, affected product prose).

IMPORTANT: CVE JSON stores affected products as *unstructured prose* in
most OT/ICS records. Machine-evaluable version bounds come from vendor
CSAF product_trees, not from CVE JSON alone.
This parser extracts metadata only — it does NOT produce applicability rules.
"""

from __future__ import annotations

import json
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def parse_cve_json(raw_json: str) -> Dict:
    """
    Parse a CVE JSON 5.1 record and return a normalised metadata dict.

    Returns:
        {
            "cve_id": str,
            "cna_org": str,           # CNA (issuing organisation)
            "state": str,             # "PUBLISHED" | "RESERVED" | ...
            "description": str,       # English description prose
            "published": str | None,
            "last_modified": str | None,
            "affected_prose": list[str],  # Raw prose affected product strings (NOT parsed)
            "references": list[str],
        }

    Raises ValueError on malformed JSON.
    """
    try:
        doc = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid CVE JSON: {}".format(exc))

    cve_meta = doc.get("cveMetadata", {})
    cve_id = cve_meta.get("cveId", "UNKNOWN")
    state = cve_meta.get("state", "UNKNOWN")
    published = cve_meta.get("datePublished")
    last_modified = cve_meta.get("dateUpdated")

    containers = doc.get("containers", {})
    cna = containers.get("cna", {})
    cna_org = cna.get("providerMetadata", {}).get("orgId", "UNKNOWN")

    # English description
    description = ""
    for desc in cna.get("descriptions", []):
        if desc.get("lang", "").startswith("en"):
            description = desc.get("value", "")
            break

    # Affected product prose — verbatim, NOT parsed into version bounds
    affected_prose: List[str] = []
    for aff in cna.get("affected", []):
        vendor = aff.get("vendor", "")
        product = aff.get("product", "")
        versions = aff.get("versions", [])
        for ver in versions:
            status = ver.get("status", "")
            version = ver.get("version", "")
            if status == "affected":
                affected_prose.append(
                    "{} {} {}".format(vendor, product, version).strip()
                )
        if not versions and (vendor or product):
            affected_prose.append("{} {}".format(vendor, product).strip())

    # References
    references: List[str] = [
        ref.get("url", "") for ref in cna.get("references", [])
        if ref.get("url", "")
    ]

    return {
        "cve_id": cve_id,
        "cna_org": cna_org,
        "state": state,
        "description": description,
        "published": published,
        "last_modified": last_modified,
        "affected_prose": affected_prose,
        "references": references,
    }

