"""
indus_probe.advisory.models
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Typed dataclasses for all advisory intelligence entities.

Python 3.9 compatible — uses Optional[X] instead of X | None,
List/Dict instead of list[X]/dict[K,V], and no match statements.

All fields that may be unknown use Optional[str] with explicit None defaults.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class VendorCode(str, enum.Enum):
    """Supported advisory vendors in Phase 1."""
    SCHNEIDER = "SCHNEIDER"
    ROCKWELL = "ROCKWELL"


class VersionScheme(str, enum.Enum):
    """
    OT firmware/software version comparison scheme.
    packaging.version (PEP 440) is explicitly NOT used here because OT
    firmware strings like 'SV3.20', '15.0 SP1', 'v33.011', 'R6.03'
    are incompatible with semver or PEP 440.
    """
    SCHNEIDER_OT = "SCHNEIDER_OT"       # SV<major>.<minor>[.<patch>] e.g. SV3.20, SV4.10
    ROCKWELL_LOGIX = "ROCKWELL_LOGIX"   # vMM.mmm  e.g. v33.011, v20.000
    SEMVER = "SEMVER"                   # M.m.p standard semver
    EXACT_ONLY = "EXACT_ONLY"           # Only equality comparisons are valid
    AMBIGUOUS_UNORDERED = "AMBIGUOUS_UNORDERED"  # Cannot be ordered; treat as UNKNOWN


class MatchState(str, enum.Enum):
    """
    8 categorical applicability states for CVE→Asset matching.

    A negative result (NO_APPLICABLE_RULE_FOUND / NOT_AFFECTED_PER_ADVISORY) for
    one advisory says NOTHING about other advisories or overall security posture.
    It is NOT a clean bill of health.
    """
    # Product is confirmed in advisory's affected tree; version is known and within affected range.
    AFFECTED_PER_ADVISORY = "AFFECTED_PER_ADVISORY"

    # Product matched; version is known and confirmed outside affected range (patched or not applicable).
    NOT_AFFECTED_PER_ADVISORY = "NOT_AFFECTED_PER_ADVISORY"

    # Product matched in affected tree; firmware/software version is not observed (passive limitation).
    PRODUCT_MATCH_VERSION_UNKNOWN = "PRODUCT_MATCH_VERSION_UNKNOWN"

    # Product matched in affected tree; version string is present but unrecognised / ambiguous scheme.
    PRODUCT_MATCH_VERSION_AMBIGUOUS = "PRODUCT_MATCH_VERSION_AMBIGUOUS"

    # Product matched BUT advisory explicitly excludes this sub-model or variant.
    PRODUCT_EXCLUDED_BY_ADVISORY = "PRODUCT_EXCLUDED_BY_ADVISORY"

    # Vendor matches but no applicable product rule exists for this specific product.
    NO_APPLICABLE_RULE_FOUND = "NO_APPLICABLE_RULE_FOUND"

    # Could not evaluate: identification basis is too weak (e.g. OUI-only, no model data).
    INSUFFICIENT_IDENTITY = "INSUFFICIENT_IDENTITY"

    # An internal evaluation error prevented a deterministic result.
    EVALUATION_ERROR = "EVALUATION_ERROR"


class IdentificationBasis(str, enum.Enum):
    """How an asset's identity was established."""
    LAB_MANIFEST = "LAB_MANIFEST"            # Explicit entry from a lab or reference document
    CLIENT_REGISTER = "CLIENT_REGISTER"      # Provided by customer asset register
    PARSED_IDENTITY = "PARSED_IDENTITY"      # Extracted from protocol negotiation (e.g. Modbus Device ID)
    OUI_INFERENCE = "OUI_INFERENCE"          # MAC OUI lookup only — weakest basis
    ANALYST_ANNOTATION = "ANALYST_ANNOTATION"  # Manual override by analyst


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class AssetFact:
    """
    Minimal evidence-backed representation of an OT asset.

    All identification fields beyond ip/mac are Optional because passive
    capture cannot guarantee visibility of model or firmware data.
    """
    ip: str
    mac: Optional[str] = None
    vendor: Optional[str] = None
    # Raw string exactly as observed or recorded; never normalised away.
    model_raw: Optional[str] = None
    # Raw firmware/software version string; not normalised to any scheme.
    firmware_version_raw: Optional[str] = None
    # Software package name (for engineering workstations, SCADA hosts).
    software_name: Optional[str] = None
    software_version_raw: Optional[str] = None
    # How identity was established.
    identification_basis: IdentificationBasis = IdentificationBasis.OUI_INFERENCE
    # Free-text provenance note (e.g. "EcoStruxure CE v14.1 from customer register p.3").
    provenance_note: Optional[str] = None
    device_hint: Optional[str] = None      # Back-compat with existing asset dicts


@dataclass
class AffectedProduct:
    """
    A single product entry from an advisory's product_tree / affected list.
    Extracted verbatim from the authoritative advisory document.
    """
    product_id: str                         # Advisory-internal ID (e.g. CSAF product_id)
    product_name: str                       # As written in the advisory
    vendor: str
    version_scheme: VersionScheme
    # Version bounds exactly as stated in the advisory — raw strings.
    version_lt: Optional[str] = None       # affected if installed_version < version_lt
    version_lte: Optional[str] = None      # affected if installed_version <= version_lte
    version_gte: Optional[str] = None      # range lower bound (inclusive)
    # "all versions" flag: set True when advisory says all versions are affected.
    all_versions: bool = False
    # Match keywords for product name normalisation (lower-case, partial match).
    match_keywords: List[str] = field(default_factory=list)
    # Source locator within the advisory document (JSONPath or section ref).
    source_locator: Optional[str] = None


@dataclass
class Advisory:
    """
    A normalised advisory record linking a CVE to its affected products.
    One advisory may cover multiple CVEs; one CVE may appear in multiple advisories.
    """
    advisory_id: str               # e.g. "SEVD-2020-343-08", "ICSA-22-090-05"
    vendor: VendorCode
    title: str
    source_url: str
    retrieval_timestamp: str       # ISO 8601
    raw_sha256: str                # SHA-256 of the fetched raw document
    file_size_bytes: int
    cve_ids: List[str] = field(default_factory=list)
    affected_products: List[AffectedProduct] = field(default_factory=list)
    # Additional metadata
    cvss_score: Optional[float] = None
    cvss_version: Optional[str] = None    # "3.1", "4.0" etc.
    cvss_vector: Optional[str] = None
    cvss_source: Optional[str] = None     # Attribution for the CVSS score
    published_date: Optional[str] = None
    revised_date: Optional[str] = None


@dataclass
class MatchResult:
    """
    Result of evaluating one advisory against one asset.

    Critical epistemic note:
      A result of NOT_AFFECTED_PER_ADVISORY or NO_APPLICABLE_RULE_FOUND
      for a specific advisory is NOT a clean bill of health.
      It says only that the evaluated advisory does not apply under the
      known evidence.  Other unevaluated advisories may still be relevant.
    """
    asset_ip: str
    advisory_id: str
    cve_id: str
    state: MatchState
    # Human-readable explanation of the evaluation logic.
    reasoning: str
    # What additional evidence would be needed to resolve an UNKNOWN outcome.
    missing_evidence: Optional[str] = None
    # Fields carried from the advisory for reporting convenience.
    advisory_title: Optional[str] = None
    vendor: Optional[str] = None
    affected_range_text: Optional[str] = None
    mitigation_note: Optional[str] = None
    # Analyst override fields (populated only after human review).
    analyst_decision: Optional[str] = None
    analyst_note: Optional[str] = None
    analyst_timestamp: Optional[str] = None

