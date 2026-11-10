"""
indus_probe.advisory.version_engine
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Custom OT firmware/software version comparators.

packaging.version (PEP 440) is explicitly NOT used here.
OT firmware strings are frequently incompatible with semver:
  - Schneider: SV3.20, SV4.10, SV4.21, 15.0 SP1
  - Rockwell:  v33.011, v20.000, v32.013
  - Yokogawa: R6.03  (Phase 2+, not implemented here)

Comparison contract:
  compare_versions(installed, boundary, scheme) → int
    negative  → installed < boundary
    zero      → installed == boundary
    positive  → installed > boundary
    raises VersionComparisonError if comparison is not possible

Design: fail loudly rather than coerce to a wrong answer.
"""

from __future__ import annotations

import logging
import re
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


class VersionComparisonError(Exception):
    """Raised when version strings cannot be meaningfully compared."""


# ---------------------------------------------------------------------------
# Schneider OT comparator
# ---------------------------------------------------------------------------
# Firmware patterns:  SV3.20  SV4.10  SV4.21
# Software patterns:  15.0 SP1  2021  v14.1  14.1
# "SV" prefix is stripped; SP suffix becomes a minor fractional component.

_SE_SV_PATTERN = re.compile(
    r"^[Ss][Vv]?(\d+)\.(\d+)(?:\.(\d+))?$"
)
_SE_SP_PATTERN = re.compile(
    r"^(\d+)\.(\d+)(?:\s+SP(\d+))?(?:\.(\d+))?$"
)
_SE_YEAR_PATTERN = re.compile(r"^(20\d\d)$")


def _parse_schneider_ot(version_str: str) -> Tuple[int, int, int, int]:
    """
    Parse a Schneider version string into a 4-tuple for comparison.
    Returns (major, minor, sp, patch).
    Raises VersionComparisonError if parsing fails.
    """
    s = version_str.strip().lstrip("vV")

    # SV-prefixed firmware: SV3.20, SV4.10
    m = _SE_SV_PATTERN.match("SV" + s) if not s.upper().startswith("SV") else _SE_SV_PATTERN.match(s)
    if m is None:
        # Try without SV prefix: 3.20, 4.10
        m = _SE_SV_PATTERN.match("SV" + s)
    if m:
        major = int(m.group(1))
        minor = int(m.group(2))
        patch = int(m.group(3)) if m.group(3) else 0
        return (major, minor, 0, patch)

    # Software version with optional SP: 15.0 SP1, 14.1, 2021
    m2 = _SE_SP_PATTERN.match(s)
    if m2:
        major = int(m2.group(1))
        minor = int(m2.group(2))
        sp = int(m2.group(3)) if m2.group(3) else 0
        patch = int(m2.group(4)) if m2.group(4) else 0
        return (major, minor, sp, patch)

    # Year-only (e.g. EcoStruxure Process Expert 2021)
    m3 = _SE_YEAR_PATTERN.match(s)
    if m3:
        return (int(m3.group(1)), 0, 0, 0)

    raise VersionComparisonError(
        "Cannot parse as Schneider OT version: {!r}".format(version_str)
    )


def _compare_schneider_ot(installed: str, boundary: str) -> int:
    """Compare two Schneider version strings. Returns negative/zero/positive."""
    t_inst = _parse_schneider_ot(installed)
    t_bnd = _parse_schneider_ot(boundary)
    if t_inst < t_bnd:
        return -1
    if t_inst > t_bnd:
        return 1
    return 0


# ---------------------------------------------------------------------------
# Rockwell Logix comparator
# ---------------------------------------------------------------------------
# Firmware patterns: v33.011  v20.000  v32.013
# Format: v<major>.<minor_zero_padded_3>

_RL_PATTERN = re.compile(r"^[vV]?(\d+)\.(\d{1,3})$")


def _parse_rockwell_logix(version_str: str) -> Tuple[int, int]:
    """
    Parse a Rockwell Logix version string.
    Returns (major, minor) where minor is treated as an integer (not decimal).
    e.g. v33.011 → (33, 11), v20.000 → (20, 0)
    """
    s = version_str.strip()
    m = _RL_PATTERN.match(s)
    if not m:
        raise VersionComparisonError(
            "Cannot parse as Rockwell Logix version: {!r}".format(version_str)
        )
    major = int(m.group(1))
    minor = int(m.group(2))  # int("011") == 11; correct for ordering
    return (major, minor)


def _compare_rockwell_logix(installed: str, boundary: str) -> int:
    t_inst = _parse_rockwell_logix(installed)
    t_bnd = _parse_rockwell_logix(boundary)
    if t_inst < t_bnd:
        return -1
    if t_inst > t_bnd:
        return 1
    return 0


# ---------------------------------------------------------------------------
# Semver comparator (simple; no pre-release)
# ---------------------------------------------------------------------------

_SEMVER_PATTERN = re.compile(r"^[vV]?(\d+)\.(\d+)(?:\.(\d+))?$")


def _parse_semver(version_str: str) -> Tuple[int, int, int]:
    s = version_str.strip()
    m = _SEMVER_PATTERN.match(s)
    if not m:
        raise VersionComparisonError(
            "Cannot parse as semver: {!r}".format(version_str)
        )
    major = int(m.group(1))
    minor = int(m.group(2))
    patch = int(m.group(3)) if m.group(3) else 0
    return (major, minor, patch)


def _compare_semver(installed: str, boundary: str) -> int:
    t_inst = _parse_semver(installed)
    t_bnd = _parse_semver(boundary)
    if t_inst < t_bnd:
        return -1
    if t_inst > t_bnd:
        return 1
    return 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compare_versions(installed: str, boundary: str, scheme: str) -> int:
    """
    Compare *installed* version string against *boundary* using the given scheme.

    Returns:
        negative  → installed < boundary  (older than boundary)
        zero      → installed == boundary
        positive  → installed > boundary  (newer than boundary)

    Raises:
        VersionComparisonError — if the scheme is EXACT_ONLY, AMBIGUOUS_UNORDERED,
                                  or if parsing fails for the named scheme.
    """
    if scheme == "SCHNEIDER_OT":
        return _compare_schneider_ot(installed, boundary)
    if scheme == "ROCKWELL_LOGIX":
        return _compare_rockwell_logix(installed, boundary)
    if scheme == "SEMVER":
        return _compare_semver(installed, boundary)
    if scheme == "EXACT_ONLY":
        if installed.strip().lower() == boundary.strip().lower():
            return 0
        raise VersionComparisonError(
            "EXACT_ONLY scheme: strings differ ({!r} vs {!r}) — cannot order them".format(
                installed, boundary
            )
        )
    if scheme == "AMBIGUOUS_UNORDERED":
        raise VersionComparisonError(
            "AMBIGUOUS_UNORDERED: version strings cannot be ordered for scheme"
        )
    raise VersionComparisonError("Unknown version scheme: {!r}".format(scheme))


def is_version_in_affected_range(
    installed_raw: str,
    version_scheme: str,
    version_lt: Optional[str] = None,
    version_lte: Optional[str] = None,
    version_gte: Optional[str] = None,
) -> Optional[bool]:
    """
    Evaluate whether *installed_raw* falls within the advisory's affected range.

    Returns:
        True   → installed version is within the affected range
        False  → installed version is outside the affected range (patched/not applicable)
        None   → comparison could not be completed (treat as UNKNOWN)
    """
    try:
        if version_lt is not None:
            cmp_lt = compare_versions(installed_raw, version_lt, version_scheme)
            lower_ok = True
            if version_gte is not None:
                cmp_gte = compare_versions(installed_raw, version_gte, version_scheme)
                lower_ok = cmp_gte >= 0
            return lower_ok and (cmp_lt < 0)

        if version_lte is not None:
            cmp_lte = compare_versions(installed_raw, version_lte, version_scheme)
            lower_ok = True
            if version_gte is not None:
                cmp_gte = compare_versions(installed_raw, version_gte, version_scheme)
                lower_ok = cmp_gte >= 0
            return lower_ok and (cmp_lte <= 0)

        # No version bounds specified at all — cannot determine range
        return None

    except VersionComparisonError as exc:
        logger.debug("Version comparison returned UNKNOWN: %s", exc)
        return None

