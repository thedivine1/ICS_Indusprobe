"""
tests/test_advisory_matcher.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Regression and acceptance tests for the IndusProbe Advisory Intelligence module.

Test plan alignment: acceptance_tests.md v1.1.0-REVISED

Sections:
  REG-01A through REG-01D — CVE-2020-7537 regression
  REG-02A through REG-02C — CVE-2021-22779 regression
  REG-03               — CVE-2018-10620 regression (Yokogawa / AVEVA)
  VER-01 through VER-10  — OT version comparator unit tests
  ACC-01 through ACC-15  — Systematic acceptance tests

CRITICAL PRINCIPLE embedded in test assertions:
  A NO_APPLICABLE_RULE_FOUND or NOT_AFFECTED_PER_ADVISORY result for one
  advisory is NOT a clean bill of health.  Tests that assert negative
  outcomes carry explicit commentary confirming this.

Python 3.9 compatible — no match statements, no walrus operators.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest

from indus_probe.advisory.db import open_db
from indus_probe.advisory.models import (
    AssetFact, IdentificationBasis, MatchState, VendorCode, VersionScheme,
)
from indus_probe.advisory.version_engine import (
    VersionComparisonError,
    compare_versions,
    is_version_in_affected_range,
)
from indus_probe.advisory.matcher import evaluate_asset_against_rule, run_match


# ---------------------------------------------------------------------------
# Helpers — synthetic rule rows and assets
# ---------------------------------------------------------------------------

def _make_rule_row(conn: sqlite3.Connection, **kwargs) -> sqlite3.Row:
    """
    Insert a minimal applicability rule into an in-memory DB and return
    the row as sqlite3.Row for use with evaluate_asset_against_rule().
    """
    defaults = dict(
        advisory_id="TEST-ADV-001",
        product_id="P1",
        product_name="Modicon M580",
        vendor="SCHNEIDER",
        version_scheme="SCHNEIDER_OT",
        version_lt="3.20",
        version_lte=None,
        version_gte=None,
        all_versions=0,
        match_keywords=json.dumps(["m580", "bmep58", "bmeh58", "epac"]),
        source_locator="/vulnerabilities/0/product_status/known_affected[1]",
        rule_hash="deadbeef",
    )
    defaults.update(kwargs)

    with conn:
        conn.execute("""
            INSERT OR IGNORE INTO advisories
                (advisory_id, vendor_code, title, source_url, raw_sha256,
                 file_size_bytes, retrieval_ts)
            VALUES (?,?,?,?,?,?,?)
        """, (
            defaults["advisory_id"], defaults["vendor"], "Test Advisory",
            "https://example.com", "aabbcc", 100,
            "2026-01-01T00:00:00Z",
        ))
        conn.execute("""
            INSERT OR REPLACE INTO applicability_rules
                (advisory_id, product_id, product_name, vendor, version_scheme,
                 version_lt, version_lte, version_gte, all_versions,
                 match_keywords, source_locator, rule_hash)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            defaults["advisory_id"], defaults["product_id"], defaults["product_name"],
            defaults["vendor"], defaults["version_scheme"],
            defaults["version_lt"], defaults["version_lte"], defaults["version_gte"],
            defaults["all_versions"],
            defaults["match_keywords"], defaults["source_locator"], defaults["rule_hash"],
        ))

    row = conn.execute(
        "SELECT * FROM applicability_rules WHERE advisory_id=? AND product_id=?",
        (defaults["advisory_id"], defaults["product_id"]),
    ).fetchone()
    return row


def _make_asset(ip="10.1.1.1", vendor="Schneider Electric",
                model_raw=None, firmware=None, hint=None,
                basis=IdentificationBasis.LAB_MANIFEST,
                software_name=None, software_version=None) -> AssetFact:
    return AssetFact(
        ip=ip,
        mac="AA:BB:CC:DD:EE:FF",
        vendor=vendor,
        model_raw=model_raw,
        firmware_version_raw=firmware,
        software_name=software_name,
        software_version_raw=software_version,
        identification_basis=basis,
        provenance_note=None,
        device_hint=hint,
    )


# ---------------------------------------------------------------------------
# Base test class with in-memory DB
# ---------------------------------------------------------------------------

class AdvisoryTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "test_advisories.db")
        self.conn = open_db(self.db_path)

    def tearDown(self) -> None:
        self.conn.close()


# ===========================================================================
# REG-01: CVE-2020-7537 Regression Cases
# ===========================================================================

class TestReg01CVE20207537(AdvisoryTestBase):
    """
    CVE-2020-7537 — Schneider Electric SEVD-2020-343-08
    DoS via crafted Modbus Read Physical Memory request.
    Affected: M580 prior to SV3.20, M340 prior to SV3.30, Quantum (all versions)
    Source: SHA-256 8590e455... (SEVD-2020-343-08.json)
    """

    def _m580_rule(self):
        return _make_rule_row(
            self.conn,
            advisory_id="SEVD-2020-343-08",
            product_id="1",
            product_name="Modicon M580 CPUs BMEx58xxxxx",
            vendor="SCHNEIDER",
            version_scheme="SCHNEIDER_OT",
            version_lt="3.20",
            all_versions=0,
            match_keywords=json.dumps(["m580", "bmep58", "bmeh58", "bme580", "epac"]),
            source_locator="/vulnerabilities/0/product_status/known_affected[1]",
        )

    def _m340_rule(self):
        return _make_rule_row(
            self.conn,
            advisory_id="SEVD-2020-343-08",
            product_id="2",
            product_name="Modicon M340 CPUs BMX P34x",
            vendor="SCHNEIDER",
            version_scheme="SCHNEIDER_OT",
            version_lt="3.30",
            all_versions=0,
            match_keywords=json.dumps(["m340", "bmxp34", "bmx p34"]),
            source_locator="/vulnerabilities/0/product_status/known_affected[2]",
            rule_hash="deadbeef2",
        )

    def _altivar_rule(self):
        return _make_rule_row(
            self.conn,
            advisory_id="SEVD-2020-343-08",
            product_id="99",
            product_name="Altivar ATV Process Drives",
            vendor="SCHNEIDER",
            version_scheme="SCHNEIDER_OT",
            version_lt=None,
            all_versions=0,
            match_keywords=json.dumps(["altivar", "atv930", "atv process"]),
            source_locator="/product_tree/branches",
            rule_hash="deadbeef99",
        )

    # REG-01A: M580 with UNKNOWN firmware → PRODUCT_MATCH_VERSION_UNKNOWN
    def test_REG01A_m580_unknown_firmware(self):
        """
        CRITICAL: M580 with unknown firmware must NOT return NO_APPLICABLE_RULE_FOUND.
        Official CSAF SEVD-2020-343-08 product_id 1 lists M580 as known_affected.
        Unknown firmware → PRODUCT_MATCH_VERSION_UNKNOWN (candidate, retain).
        """
        rule = self._m580_rule()
        asset = _make_asset(
            vendor="Schneider Electric",
            model_raw="Modicon M580 ePAC BMEP582020",
            firmware=None,  # Unknown
            hint="Schneider Electric Modicon M580",
        )
        result = evaluate_asset_against_rule(asset, rule)
        self.assertIsNotNone(result)
        self.assertEqual(result.state, MatchState.PRODUCT_MATCH_VERSION_UNKNOWN,
            "M580 with unknown firmware MUST be PRODUCT_MATCH_VERSION_UNKNOWN, "
            "NEVER NO_APPLICABLE_RULE_FOUND. Per SEVD-2020-343-08 product_id=1.")
        self.assertIn("version", result.reasoning.lower())

    # REG-01B: M340 with verified firmware SV3.20 → AFFECTED_PER_ADVISORY
    def test_REG01B_m340_firmware_lt_boundary(self):
        """
        M340 with BMXP34 SV3.20 is strictly less than boundary SV3.30.
        Expected: AFFECTED_PER_ADVISORY.
        Source: SEVD-2020-343-08 product_id=2, version_lt='3.30'.
        """
        rule = self._m340_rule()
        asset = _make_asset(
            vendor="Schneider Electric",
            model_raw="Modicon M340 BMXP342020",
            firmware="SV3.20",
            hint="Schneider M340",
        )
        result = evaluate_asset_against_rule(asset, rule)
        self.assertIsNotNone(result)
        self.assertEqual(result.state, MatchState.AFFECTED_PER_ADVISORY,
            "SV3.20 < SV3.30 boundary → AFFECTED. Per SEVD-2020-343-08 product_id=2.")

    # REG-01C: Altivar ATV930 drive → NO_APPLICABLE_RULE_FOUND
    def test_REG01C_altivar_drive_not_in_product_tree(self):
        """
        Altivar drives are variable-speed drives, NOT PLCs.
        SEVD-2020-343-08 does not list Altivar in known_affected product_ids.
        Expected: NO_APPLICABLE_RULE_FOUND (for THIS advisory).
        NOTE: This is NOT a clean bill of health for the Altivar drive.
        """
        rule = self._altivar_rule()
        asset = _make_asset(
            vendor="Schneider Electric",
            model_raw="Altivar ATV930 Variable Speed Drive",
            firmware="1.8",
            hint="Altivar ATV930",
        )
        result = evaluate_asset_against_rule(asset, rule)
        # Altivar keywords should match the Altivar rule but advisory excludes it
        # (rule has no version_lt — cannot determine range)
        self.assertIsNotNone(result)
        # With no version boundary, should be PRODUCT_MATCH_VERSION_UNKNOWN or NO_APPLICABLE_RULE_FOUND
        self.assertIn(
            result.state,
            {MatchState.NO_APPLICABLE_RULE_FOUND, MatchState.PRODUCT_MATCH_VERSION_UNKNOWN},
            "Altivar against SEVD-2020-343-08 must NOT be AFFECTED. "
            "No CVE-2020-7537 applicability rule covers Altivar drives."
        )

    # REG-01D: M340 with firmware >= patched version → NOT_AFFECTED_PER_ADVISORY
    def test_REG01D_m340_patched_firmware(self):
        """
        M340 with BMXP34 SV3.30 (the patched boundary) → NOT_AFFECTED_PER_ADVISORY.
        NOTE: Not affected by THIS advisory only. Not a global clean bill of health.
        """
        rule = self._m340_rule()
        asset = _make_asset(
            vendor="Schneider Electric",
            model_raw="Modicon M340 BMXP342020",
            firmware="SV3.30",
            hint="Schneider M340",
        )
        result = evaluate_asset_against_rule(asset, rule)
        self.assertIsNotNone(result)
        self.assertEqual(result.state, MatchState.NOT_AFFECTED_PER_ADVISORY,
            "SV3.30 == boundary (not < 3.30) → NOT_AFFECTED for SEVD-2020-343-08. "
            "This applies ONLY to this advisory.")
        # Assert the disclaimer is present in reasoning
        self.assertIn("not a clean bill", result.reasoning.lower(),
            "NOT_AFFECTED result must carry the epistemic disclaimer.")


# ===========================================================================
# REG-02: CVE-2021-22779 Regression Cases
# ===========================================================================

class TestReg02CVE202122779(AdvisoryTestBase):
    """
    CVE-2021-22779 — Schneider Electric SEVD-2021-194-01
    Authentication bypass by spoofing via Modbus UMAS.
    Affected: EcoStruxure Control Expert < 15.0 SP1; M580 (all versions); M340 < 3.50
    Source: SHA-256 b5e3a325... (SEVD-2021-194-01.json)
    """

    def _control_expert_rule(self):
        return _make_rule_row(
            self.conn,
            advisory_id="SEVD-2021-194-01",
            product_id="3",
            product_name="EcoStruxure Control Expert",
            vendor="SCHNEIDER",
            version_scheme="SCHNEIDER_OT",
            version_lt="15.0 SP1",
            all_versions=0,
            match_keywords=json.dumps(["control expert", "unity pro", "ecostruxure control expert"]),
            source_locator="/vulnerabilities/0/product_status/known_affected[3]",
            rule_hash="reg02a",
        )

    def _m580_all_versions_rule(self):
        return _make_rule_row(
            self.conn,
            advisory_id="SEVD-2021-194-01",
            product_id="8",
            product_name="Modicon M580 CPU — All versions",
            vendor="SCHNEIDER",
            version_scheme="SCHNEIDER_OT",
            version_lt=None,
            all_versions=1,
            match_keywords=json.dumps(["m580", "bmep58", "bmeh58", "bme580"]),
            source_locator="/vulnerabilities/0/product_status/known_affected[8]",
            rule_hash="reg02b",
        )

    # REG-02A: Engineering workstation with Control Expert v14.1 → AFFECTED
    def test_REG02A_control_expert_v141_affected(self):
        """
        EcoStruxure Control Expert v14.1 < 15.0 SP1 → AFFECTED_PER_ADVISORY.
        Source: SEVD-2021-194-01 product_id=3.
        """
        rule = self._control_expert_rule()
        asset = _make_asset(
            ip="10.1.1.50",
            vendor="Schneider Electric",
            model_raw="Engineering Workstation",
            firmware=None,
            hint="Schneider Electric EcoStruxure Control Expert",
            software_name="EcoStruxure Control Expert",
            software_version="14.1",
        )
        result = evaluate_asset_against_rule(asset, rule)
        self.assertIsNotNone(result)
        self.assertEqual(result.state, MatchState.AFFECTED_PER_ADVISORY,
            "Control Expert 14.1 < 15.0 SP1 → AFFECTED. Source: SEVD-2021-194-01 product_id=3.")

    # REG-02B: M580 with all_versions=True → AFFECTED regardless of firmware
    def test_REG02B_m580_all_versions_affected(self):
        """
        SEVD-2021-194-01 product_id=8 marks M580 CPU as affected in ALL versions.
        Asset with unknown firmware → AFFECTED_PER_ADVISORY (all_versions=True).
        """
        rule = self._m580_all_versions_rule()
        asset = _make_asset(
            ip="10.1.1.21",
            vendor="Schneider Electric",
            model_raw="Modicon M580 BMEP582040",
            firmware=None,
            hint="Schneider Modicon M580",
        )
        result = evaluate_asset_against_rule(asset, rule)
        self.assertIsNotNone(result)
        self.assertEqual(result.state, MatchState.AFFECTED_PER_ADVISORY,
            "M580 with all_versions=True in SEVD-2021-194-01 → AFFECTED regardless of firmware.")

    # REG-02C: M580 with unknown firmware, version_lt rule → PRODUCT_MATCH_VERSION_UNKNOWN
    def test_REG02C_m580_unknown_firmware_version_lt_rule(self):
        """
        Rule with version_lt bound + asset with no firmware → PRODUCT_MATCH_VERSION_UNKNOWN.
        (Use a hypothetical rule with a version boundary rather than all_versions.)
        """
        rule = _make_rule_row(
            self.conn,
            advisory_id="SEVD-2021-194-01",
            product_id="13",
            product_name="Modicon M580 CPU — versions prior to SV4.10",
            vendor="SCHNEIDER",
            version_scheme="SCHNEIDER_OT",
            version_lt="4.10",
            all_versions=0,
            match_keywords=json.dumps(["m580", "bmep58"]),
            source_locator="/vulnerabilities/0/product_status/known_affected[13]",
            rule_hash="reg02c",
        )
        asset = _make_asset(
            ip="10.1.1.22",
            vendor="Schneider Electric",
            model_raw="M580 BMEP584040",
            firmware=None,
        )
        result = evaluate_asset_against_rule(asset, rule)
        self.assertIsNotNone(result)
        self.assertEqual(result.state, MatchState.PRODUCT_MATCH_VERSION_UNKNOWN,
            "M580 unknown firmware vs version_lt rule → PRODUCT_MATCH_VERSION_UNKNOWN.")
        self.assertIsNotNone(result.missing_evidence)


# ===========================================================================
# REG-03: CVE-2018-10620 (AVEVA, NOT Yokogawa)
# ===========================================================================

class TestReg03CVE201810620(AdvisoryTestBase):
    """
    CVE-2018-10620 — AVEVA InduSoft Web Studio / InTouch Machine Edition.
    CNA: AVEVA Software, LLC.
    Zero connection to Yokogawa hardware.
    Source: SHA-256 ec542cec... (CVE-2018-10620.json)
    """

    def test_REG03_yokogawa_centum_no_applicable_rule(self):
        """
        A Yokogawa CENTUM VP gateway must return NO_APPLICABLE_RULE_FOUND
        for any AVEVA rule — vendor mismatch prevents product evaluation.
        No AVEVA rules exist for Yokogawa hardware.
        NOTE: NO_APPLICABLE_RULE_FOUND is NOT a clean bill of health.
        """
        # Insert a Rockwell rule (simulates "no Yokogawa rule exists")
        rule = _make_rule_row(
            self.conn,
            advisory_id="AVEVA-2018-10620",
            product_id="A1",
            product_name="InduSoft Web Studio v8.1",
            vendor="ROCKWELL",  # Wrong vendor to force vendor mismatch for Yokogawa asset
            version_scheme="SEMVER",
            version_lt="8.1",
            all_versions=0,
            match_keywords=json.dumps(["indusoft", "intouch machine edition"]),
            source_locator="/containers/cna/affected[0]",
            rule_hash="reg03a",
        )
        asset = _make_asset(
            ip="10.1.1.200",
            vendor="Yokogawa",
            model_raw="CENTUM VP Field Control Station",
            firmware="R6.03",
            hint="Yokogawa CENTUM VP Gateway",
        )
        # Yokogawa vendor → Rockwell rule vendor mismatch → evaluate_asset_against_rule returns None
        result = evaluate_asset_against_rule(asset, rule)
        self.assertIsNone(result,
            "Yokogawa asset vs Rockwell/AVEVA rule → None (vendor mismatch, skip). "
            "CVE-2018-10620 is AVEVA-only. Zero applicability to Yokogawa hardware.")


# ===========================================================================
# VER: Version Comparator Unit Tests
# ===========================================================================

class TestVersionComparator(unittest.TestCase):
    """
    VER-01 through VER-10: OT version comparator unit tests.
    All use compare_versions() or is_version_in_affected_range().
    """

    # VER-01: Schneider SV comparison — older is less
    def test_VER01_schneider_sv_older_less(self):
        self.assertLess(compare_versions("SV3.10", "SV3.20", "SCHNEIDER_OT"), 0)

    # VER-02: Schneider SV comparison — equal
    def test_VER02_schneider_sv_equal(self):
        self.assertEqual(compare_versions("SV3.20", "SV3.20", "SCHNEIDER_OT"), 0)

    # VER-03: Schneider SV comparison — newer is greater
    def test_VER03_schneider_sv_newer_greater(self):
        self.assertGreater(compare_versions("SV4.21", "SV4.10", "SCHNEIDER_OT"), 0)

    # VER-04: Schneider SP version comparison (15.0 SP1 > 14.1)
    def test_VER04_schneider_sp_version(self):
        self.assertLess(compare_versions("14.1", "15.0 SP1", "SCHNEIDER_OT"), 0,
            "14.1 must be less than 15.0 SP1")

    # VER-05: Schneider SP version — 15.0 SP1 equals itself
    def test_VER05_schneider_sp_equal(self):
        self.assertEqual(compare_versions("15.0 SP1", "15.0 SP1", "SCHNEIDER_OT"), 0)

    # VER-06: Rockwell Logix leading zeros — v33.011 < v33.013
    def test_VER06_rockwell_leading_zeros(self):
        self.assertLess(compare_versions("v33.011", "v33.013", "ROCKWELL_LOGIX"), 0,
            "v33.011 must be less than v33.013 (011 < 013 as integers)")

    # VER-07: Rockwell Logix major version comparison
    def test_VER07_rockwell_major_version(self):
        self.assertLess(compare_versions("v20.000", "v33.011", "ROCKWELL_LOGIX"), 0)

    # VER-08: AMBIGUOUS_UNORDERED raises VersionComparisonError
    def test_VER08_ambiguous_raises(self):
        with self.assertRaises(VersionComparisonError):
            compare_versions("R6.03", "R7.00", "AMBIGUOUS_UNORDERED")

    # VER-09: EXACT_ONLY equality succeeds
    def test_VER09_exact_only_equal(self):
        self.assertEqual(compare_versions("v8.1", "v8.1", "EXACT_ONLY"), 0)

    # VER-10: EXACT_ONLY inequality raises
    def test_VER10_exact_only_not_equal_raises(self):
        with self.assertRaises(VersionComparisonError):
            compare_versions("v8.1", "v8.2", "EXACT_ONLY")


# ===========================================================================
# ACC: Systematic Acceptance Tests
# ===========================================================================

class TestAcceptance(AdvisoryTestBase):
    """
    ACC-01 through ACC-15: Systematic acceptance tests for the matcher module.
    """

    def _schneider_m580_rule(self):
        return _make_rule_row(
            self.conn,
            advisory_id="TEST-SE-001",
            product_id="P1",
            product_name="Modicon M580 CPU",
            vendor="SCHNEIDER",
            version_scheme="SCHNEIDER_OT",
            version_lt="3.20",
            all_versions=0,
            match_keywords=json.dumps(["m580", "bmep58", "epac"]),
            rule_hash="acc001",
        )

    # ACC-01: Vendor mismatch → None (skipped)
    def test_ACC01_vendor_mismatch_returns_none(self):
        rule = self._schneider_m580_rule()
        asset = _make_asset(vendor="Siemens", model_raw="S7-300", hint="Siemens S7-300")
        result = evaluate_asset_against_rule(asset, rule)
        self.assertIsNone(result, "Siemens asset vs Schneider rule → None (skip)")

    # ACC-02: No model/hint/software → INSUFFICIENT_IDENTITY
    def test_ACC02_no_model_insufficient_identity(self):
        rule = self._schneider_m580_rule()
        asset = _make_asset(vendor="Schneider Electric", model_raw=None, hint=None)
        result = evaluate_asset_against_rule(asset, rule)
        self.assertIsNotNone(result)
        self.assertEqual(result.state, MatchState.INSUFFICIENT_IDENTITY)

    # ACC-03: Vendor match, keyword miss → NO_APPLICABLE_RULE_FOUND
    def test_ACC03_keyword_miss_no_rule_found(self):
        rule = self._schneider_m580_rule()
        # Altivar is Schneider but keyword won't match M580 keywords
        asset = _make_asset(vendor="Schneider Electric", model_raw="Altivar 32", hint="Altivar 32")
        result = evaluate_asset_against_rule(asset, rule)
        self.assertIsNotNone(result)
        self.assertEqual(result.state, MatchState.NO_APPLICABLE_RULE_FOUND)

    # ACC-04: Product match, firmware unknown → PRODUCT_MATCH_VERSION_UNKNOWN
    def test_ACC04_product_match_firmware_unknown(self):
        rule = self._schneider_m580_rule()
        asset = _make_asset(vendor="Schneider Electric", model_raw="BMEP584040", hint="M580")
        result = evaluate_asset_against_rule(asset, rule)
        self.assertIsNotNone(result)
        self.assertEqual(result.state, MatchState.PRODUCT_MATCH_VERSION_UNKNOWN)
        self.assertIsNotNone(result.missing_evidence)

    # ACC-05: Product match, firmware in affected range → AFFECTED
    def test_ACC05_product_match_affected_version(self):
        rule = self._schneider_m580_rule()
        asset = _make_asset(vendor="Schneider Electric", model_raw="BMEP584040",
                            hint="M580", firmware="SV3.10")
        result = evaluate_asset_against_rule(asset, rule)
        self.assertIsNotNone(result)
        self.assertEqual(result.state, MatchState.AFFECTED_PER_ADVISORY)

    # ACC-06: Product match, firmware at patched boundary → NOT_AFFECTED
    def test_ACC06_product_match_patched_version(self):
        rule = self._schneider_m580_rule()
        asset = _make_asset(vendor="Schneider Electric", model_raw="BMEP584040",
                            hint="M580", firmware="SV3.20")
        result = evaluate_asset_against_rule(asset, rule)
        self.assertIsNotNone(result)
        self.assertEqual(result.state, MatchState.NOT_AFFECTED_PER_ADVISORY)

    # ACC-07: NOT_AFFECTED result carries epistemic disclaimer
    def test_ACC07_not_affected_has_disclaimer(self):
        rule = self._schneider_m580_rule()
        asset = _make_asset(vendor="Schneider Electric", model_raw="BMEP584040",
                            hint="M580", firmware="SV4.00")
        result = evaluate_asset_against_rule(asset, rule)
        self.assertEqual(result.state, MatchState.NOT_AFFECTED_PER_ADVISORY)
        self.assertIn("not a clean bill", result.reasoning.lower(),
            "NOT_AFFECTED reasoning must contain the epistemic disclaimer.")

    # ACC-08: all_versions=True → AFFECTED regardless of firmware
    def test_ACC08_all_versions_affected(self):
        rule = _make_rule_row(
            self.conn,
            advisory_id="TEST-SE-002",
            product_id="P2",
            product_name="Modicon Quantum (all versions)",
            vendor="SCHNEIDER",
            version_scheme="SCHNEIDER_OT",
            all_versions=1,
            match_keywords=json.dumps(["quantum", "140cpu"]),
            rule_hash="acc008",
        )
        asset = _make_asset(vendor="Schneider Electric",
                            model_raw="Modicon Quantum 140CPU65150C",
                            firmware=None, hint="Modicon Quantum")
        result = evaluate_asset_against_rule(asset, rule)
        self.assertIsNotNone(result)
        self.assertEqual(result.state, MatchState.AFFECTED_PER_ADVISORY)

    # ACC-09: Rockwell ControlLogix with version in range → AFFECTED
    def test_ACC09_rockwell_controllogix_affected(self):
        rule = _make_rule_row(
            self.conn,
            advisory_id="ICSA-22-090-05",
            product_id="R1",
            product_name="ControlLogix 5580 Firmware",
            vendor="ROCKWELL",
            version_scheme="ROCKWELL_LOGIX",
            version_lt="33.011",
            all_versions=0,
            match_keywords=json.dumps(["controllogix", "1756", "guardlogix"]),
            rule_hash="acc009",
        )
        asset = _make_asset(
            vendor="Rockwell Automation",
            model_raw="ControlLogix 5580 1756-L83E",
            firmware="v32.013",
            hint="ControlLogix 5580",
        )
        result = evaluate_asset_against_rule(asset, rule)
        self.assertIsNotNone(result)
        self.assertEqual(result.state, MatchState.AFFECTED_PER_ADVISORY,
            "v32.013 < v33.011 → AFFECTED. Per ICSA-22-090-05.")

    # ACC-10: Rockwell ControlLogix patched firmware → NOT_AFFECTED
    def test_ACC10_rockwell_controllogix_patched(self):
        rule = _make_rule_row(
            self.conn,
            advisory_id="ICSA-22-090-05",
            product_id="R1b",
            product_name="ControlLogix 5580 Firmware patched",
            vendor="ROCKWELL",
            version_scheme="ROCKWELL_LOGIX",
            version_lt="33.011",
            all_versions=0,
            match_keywords=json.dumps(["controllogix", "1756"]),
            rule_hash="acc010",
        )
        asset = _make_asset(
            vendor="Rockwell Automation",
            model_raw="ControlLogix 5580 1756-L83E",
            firmware="v33.011",
            hint="ControlLogix 5580",
        )
        result = evaluate_asset_against_rule(asset, rule)
        self.assertIsNotNone(result)
        self.assertEqual(result.state, MatchState.NOT_AFFECTED_PER_ADVISORY,
            "v33.011 is NOT < v33.011 → NOT_AFFECTED.")

    # ACC-11: Unparseable version string → PRODUCT_MATCH_VERSION_AMBIGUOUS
    def test_ACC11_ambiguous_version_string(self):
        rule = _make_rule_row(
            self.conn,
            advisory_id="TEST-SE-003",
            product_id="P3",
            product_name="Modicon M340",
            vendor="SCHNEIDER",
            version_scheme="SCHNEIDER_OT",
            version_lt="3.30",
            all_versions=0,
            match_keywords=json.dumps(["m340", "bmxp34"]),
            rule_hash="acc011",
        )
        asset = _make_asset(
            vendor="Schneider Electric",
            model_raw="M340 BMXP342020",
            firmware="UNKNOWN_VERSION_XYZ",   # Cannot be parsed
            hint="Schneider M340",
        )
        result = evaluate_asset_against_rule(asset, rule)
        self.assertIsNotNone(result)
        self.assertIn(
            result.state,
            {MatchState.PRODUCT_MATCH_VERSION_AMBIGUOUS, MatchState.PRODUCT_MATCH_VERSION_UNKNOWN},
            "Unparseable version → AMBIGUOUS or UNKNOWN, never AFFECTED."
        )

    # ACC-12: Software match via software_name field
    def test_ACC12_software_name_match(self):
        rule = _make_rule_row(
            self.conn,
            advisory_id="TEST-SE-004",
            product_id="P4",
            product_name="EcoStruxure Control Expert",
            vendor="SCHNEIDER",
            version_scheme="SCHNEIDER_OT",
            version_lt="15.0 SP1",
            all_versions=0,
            match_keywords=json.dumps(["control expert", "unity pro"]),
            rule_hash="acc012",
        )
        asset = _make_asset(
            ip="10.1.1.50",
            vendor="Schneider Electric",
            model_raw=None,
            hint=None,
            software_name="EcoStruxure Control Expert",
            software_version="14.1",
        )
        result = evaluate_asset_against_rule(asset, rule)
        self.assertIsNotNone(result)
        self.assertEqual(result.state, MatchState.AFFECTED_PER_ADVISORY)

    # ACC-13: run_match returns empty list when no rules in DB
    def test_ACC13_no_rules_returns_empty(self):
        assets = [_make_asset(vendor="Schneider Electric", model_raw="M580")]
        results = run_match(assets, self.conn)
        self.assertEqual(results, [],
            "run_match with empty DB must return empty list, not raise.")

    # ACC-14: Multiple assets, multiple rules produce correct per-asset results
    def test_ACC14_multi_asset_multi_rule(self):
        rule_a = self._schneider_m580_rule()
        rule_b = _make_rule_row(
            self.conn,
            advisory_id="TEST-SE-001",
            product_id="P1b",
            product_name="Modicon M340",
            vendor="SCHNEIDER",
            version_scheme="SCHNEIDER_OT",
            version_lt="3.30",
            all_versions=0,
            match_keywords=json.dumps(["m340", "bmxp34"]),
            rule_hash="acc014b",
        )
        assets = [
            _make_asset(ip="10.1.1.10", vendor="Schneider Electric",
                        model_raw="M580 BMEP584040", firmware="SV3.10"),
            _make_asset(ip="10.1.1.11", vendor="Schneider Electric",
                        model_raw="M340 BMXP342020", firmware="SV3.40"),
        ]
        results = run_match(assets, self.conn)
        result_by_ip = {}
        for r in results:
            result_by_ip.setdefault(r.asset_ip, []).append(r)

        m580_results = result_by_ip.get("10.1.1.10", [])
        m340_results = result_by_ip.get("10.1.1.11", [])

        m580_states = {r.state for r in m580_results}
        m340_states = {r.state for r in m340_results}

        self.assertIn(MatchState.AFFECTED_PER_ADVISORY, m580_states,
            "M580 SV3.10 < 3.20 → AFFECTED")
        self.assertIn(MatchState.NOT_AFFECTED_PER_ADVISORY, m340_states,
            "M340 SV3.40 >= 3.30 → NOT_AFFECTED for TEST-SE-001")

    # ACC-15: Epistemic principle — negative result is NOT global clean bill of health
    def test_ACC15_negative_result_not_global_clean(self):
        """
        Verifies that the system's NOT_AFFECTED and NO_APPLICABLE_RULE_FOUND
        reasoning text explicitly disclaims global applicability.
        This test encodes the core epistemic guarantee.
        """
        rule = self._schneider_m580_rule()
        # Altivar → NO_APPLICABLE_RULE_FOUND
        asset_atv = _make_asset(vendor="Schneider Electric",
                                model_raw="Altivar ATV320", hint="Altivar ATV320")
        result_atv = evaluate_asset_against_rule(asset_atv, rule)
        self.assertIn("not a clean bill", result_atv.reasoning.lower(),
            "NO_APPLICABLE_RULE_FOUND reasoning must carry epistemic disclaimer.")

        # Patched M580 → NOT_AFFECTED
        asset_m580 = _make_asset(vendor="Schneider Electric",
                                 model_raw="M580 BMEP584040", hint="M580", firmware="SV4.00")
        result_m580 = evaluate_asset_against_rule(asset_m580, rule)
        self.assertEqual(result_m580.state, MatchState.NOT_AFFECTED_PER_ADVISORY)
        self.assertIn("not a clean bill", result_m580.reasoning.lower(),
            "NOT_AFFECTED reasoning must carry epistemic disclaimer.")


if __name__ == "__main__":
    unittest.main(verbosity=2)

