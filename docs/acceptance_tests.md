# IndusProbe Advisory Intelligence — Acceptance Tests & Regression Suite
## Comprehensive Test Plan & Verification Criteria

**Document Version:** 1.1.0-REVISED  
**Date:** 2026-11-10  
**Test Harness:** `pytest` (100% Offline Test Fixtures)  
**Status:** PROPOSED — PENDING ARCHITECTURAL APPROVAL  

---

## 1. Test Strategy & Air-Gap Enforcement

1. **Strict Offline Air-Gap**: The test harness installs a socket monkeypatch (`socket.socket = blocked_socket`) that raises an immediate exception if any outbound network call is attempted during normalization or matching.
2. **Authoritative Fixture Grounding**: Real CVE tests use official JSON/CSAF test fixtures downloaded and archived in `tests/fixtures/advisories/`. Edge-case tests use explicitly labeled synthetic identifiers (e.g. `SYNTHETIC-CVE-2026-0001`).
3. **Epistemic Clarity**: A negative result for a specific CVE confirms only that the evaluated advisory does not match the asset. It is never treated as a general assurance that the asset has no vulnerabilities.

---

## 2. Benchmark Regression Test Suite (Official Records)

The three benchmark CVEs are grounded in retrieved authoritative records (`CVEProject/cvelistV5` and Schneider Electric CSAF repository):

### 2.1 Benchmark Cases Specification

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       BENCHMARK REGRESSION CASES SPECIFICATION                                        │
├─────────────────┬──────────────────────┬──────────────────────┬────────────────────────┬───────────────────────────────┤
│ Case ID         │ Evaluated CVE        │ Source Artifact      │ Target Asset Facts     │ Expected Categorical Outcome  │
├─────────────────┼──────────────────────┼──────────────────────┼────────────────────────┼───────────────────────────────┤
│ **REG-01A**     │ **CVE-2020-7537**    │ `sevd-2020-343-08`   │ M580 (Firmware UNK)    │ `PRODUCT_MATCH_VERSION_UNKNOWN`│
│ **REG-01B**     │ **CVE-2020-7537**    │ `sevd-2020-343-08`   │ M580 (Firmware 3.10)   │ `AFFECTED_PER_ADVISORY`        │
│ **REG-01C**     │ **CVE-2020-7537**    │ `sevd-2020-343-08`   │ M580 (Firmware 3.20)   │ `NOT_AFFECTED_PER_ADVISORY`    │
│ **REG-01D**     │ **CVE-2020-7537**    │ `sevd-2020-343-08`   │ Altivar ATV930 Drive   │ `NO_APPLICABLE_RULE_FOUND`     │
│ **REG-02A**     │ **CVE-2021-22779**    │ `sevd-2021-194-01`   │ Control Expert 14.1    │ `AFFECTED_PER_ADVISORY`        │
│ **REG-02B**     │ **CVE-2021-22779**    │ `sevd-2021-194-01`   │ Control Expert 15.0 SP1│ `NOT_AFFECTED_PER_ADVISORY`    │
│ **REG-02C**     │ **CVE-2021-22779**    │ `sevd-2021-194-01`   │ M580 (Firmware UNK)    │ `PRODUCT_MATCH_VERSION_UNKNOWN`│
│ **REG-03**      │ **CVE-2018-10620**    │ `CVE-2018-10620.json`│ Yokogawa CENTUM VP GW  │ `NO_APPLICABLE_RULE_FOUND`     │
└─────────────────┴──────────────────────┴──────────────────────┴────────────────────────┴───────────────────────────────┘
```

### Detailed Case Analysis
* **Case REG-01A (M580 Unknown Firmware vs CVE-2020-7537)**:
  * **Source Locator**: `/vulnerabilities/0/product_status/known_affected` (Product ID `1` = `Modicon M580 CPUs prior to version 3.20`).
  * **Asset Facts**: Vendor: `Schneider Electric`, Model: `Modicon M580 ePAC`, Firmware: `None` (Unknown).
  * **Expected Outcome**: **`PRODUCT_MATCH_VERSION_UNKNOWN`** (Candidate advisory; firmware unknown).
  * **Reasoning**: Product line matches advisory. Because firmware is unobserved, declaring it unaffected is a catastrophic error; declaring it affected without evidence is a false positive. Candidate state is the only mathematically defensible outcome.
  * **Missing Evidence**: Installed controller firmware version.
* **Case REG-01B (M580 Affected Firmware vs CVE-2020-7537)**:
  * **Asset Facts**: Vendor: `Schneider Electric`, Model: `Modicon M580 ePAC`, Firmware: `3.10`.
  * **Expected Outcome**: **`AFFECTED_PER_ADVISORY`** (`3.10 < 3.20`).
* **Case REG-01C (M580 Fixed Firmware vs CVE-2020-7537)**:
  * **Source Locator**: `/vulnerabilities/0/product_status/fixed` (Product ID `5` = `Modicon M580 CPUs 3.20`).
  * **Asset Facts**: Vendor: `Schneider Electric`, Model: `Modicon M580 ePAC`, Firmware: `3.20`.
  * **Expected Outcome**: **`NOT_AFFECTED_PER_ADVISORY`** (Firmware equals fixed release).
* **Case REG-01D (Same Vendor Wrong Product vs CVE-2020-7537)**:
  * **Asset Facts**: Vendor: `Schneider Electric`, Model: `Altivar Process ATV930 Drive`, Firmware: `v1.8`.
  * **Expected Outcome**: **`NO_APPLICABLE_RULE_FOUND`** (Altivar drive is not in Modicon CPU product tree).
* **Case REG-02A (Control Expert Software vs CVE-2021-22779)**:
  * **Source Locator**: `/vulnerabilities/0/product_status/known_affected` (Product ID `3` = `Control Expert versions prior to 15.0 SP1`).
  * **Asset Facts**: Vendor: `Schneider Electric`, Model: `Engineering Station`, Installed Software: `EcoStruxure Control Expert v14.1`.
  * **Expected Outcome**: **`AFFECTED_PER_ADVISORY`** (`14.1 < 15.0 SP1`).
* **Case REG-03 (Yokogawa Gateway vs CVE-2018-10620)**:
  * **Source Locator**: `/containers/cna/affected/0` (Product = `AVEVA InduSoft Web Studio / InTouch Machine Edition`).
  * **Asset Facts**: Vendor: `Yokogawa`, Model: `CENTUM VP Gas Analyzer Gateway`, Firmware: `R6.03`.
  * **Expected Outcome**: **`NO_APPLICABLE_RULE_FOUND`** (CVE belongs to AVEVA software; zero relation to Yokogawa).

---

## 3. Dedicated OT Version Comparator Tests

These tests validate that OT firmware versions are compared correctly without relying on Python `packaging.version`.

| Test ID | Comparator Scheme | Inputs (Installed vs Rule) | Expected Ordering / Result | Technical Reasoning |
|---|---|---|---|---|
| **VER-01** | `SCHNEIDER_OT` | Installed: `SV3.20`, Rule: `< SV3.30` | `TRUE` (`AFFECTED`) | Prefix `SV` stripped; minor version `20 < 30`. |
| **VER-02** | `SCHNEIDER_OT` | Installed: `SV3.30`, Rule: `< SV3.30` | `FALSE` (`NOT_AFFECTED`) | Strict inequality; `3.30` is not `< 3.30`. |
| **VER-03** | `SCHNEIDER_OT` | Installed: `15.0 SP1`, Rule: `< 15.0 SP1` | `FALSE` (`NOT_AFFECTED`) | Service pack suffix parsed; fixed threshold met. |
| **VER-04** | `SCHNEIDER_OT` | Installed: `15.0`, Rule: `< 15.0 SP1` | `TRUE` (`AFFECTED`) | Base release `15.0` is strictly older than `15.0 SP1`. |
| **VER-05** | `ROCKWELL_LOGIX` | Installed: `v33.011`, Rule: `< v33.011` | `FALSE` (`NOT_AFFECTED`) | Numerical component match; not strictly less. |
| **VER-06** | `ROCKWELL_LOGIX` | Installed: `v33.010`, Rule: `< v33.011` | `TRUE` (`AFFECTED`) | Minor component `10 < 11`. |
| **VER-07** | `ROCKWELL_LOGIX` | Installed: `v33.01`, Rule: `== v33.1` | `TRUE` (`EQUIVALENT`) | Leading zero in minor integer normalized. |
| **VER-08** | Hardware Series | Installed: `1756-L83E Series B`, Rule: `Series A only` | `FALSE` (`SERIES_MISMATCH`) | Hardware series mismatch halts version evaluation. |
| **VER-09** | Inclusive Bound | Installed: `v2.4`, Rule: `<= v2.4` | `TRUE` (`AFFECTED`) | `max_inclusive = 1` evaluates `<=` correctly. |
| **VER-10** | Ambiguous Fallback | Installed: `Rel_Beta_Test`, Rule: `< 2.0` | `UNKNOWN` | Unparseable format returns `UNKNOWN`; never guesses. |

---

## 4. Systematic Acceptance Test Matrix

| Test ID | Category | Scenario / Inputs | Expected Assertion |
|---|---|---|---|
| **ACC-01** | Vendor-Only Decoupling | Asset has Vendor="Schneider Electric", but device is Altivar ATV930 drive. Rule targets Modicon M580. | Categorical status = `NO_APPLICABLE_RULE_FOUND`. Vendor match alone never triggers rule. |
| **ACC-02** | Protocol-Only Decoupling | Asset seen transmitting Modbus TCP (port 502), but device identity is Unknown. | Categorical status = `INSUFFICIENT_IDENTITY`. Protocol presence alone cannot match CVE. |
| **ACC-03** | Missing Firmware Handling | Asset is verified `Schneider Modicon M580`, but firmware version is unobserved. | Categorical status = `PRODUCT_MATCH_VERSION_UNKNOWN`. Never declare confirmed affected. |
| **ACC-04** | Fixed Version Enforcement | Asset firmware matches patched version declared in CSAF `fixed` array. | Categorical status = `NOT_AFFECTED_PER_ADVISORY`. Reported as patched. |
| **ACC-05** | Prerequisite Uncertainty | Advisory requires `Embedded Web Server enabled`. Asset configuration is unobserved. | Categorical status = `VERSION_MATCH_CONDITIONS_UNKNOWN`. Prerequisite reported as unknown. |
| **ACC-06** | Contradictory Sources | Vendor CSAF states `NOT_AFFECTED`, but CNA CVE record lists `affected`. | Categorical status = `CONFLICT_REQUIRES_REVIEW`. Flagged for human review. |
| **ACC-07** | Advisory Revision Trigger | Advisory rev 1 ingested; advisory rev 2 ingested with updated fixed versions. | Re-evaluation triggers automatic recalculation; previously stored match is marked superseded. |
| **ACC-08** | SSRF Security Filter | Harvester supplied URL `http://169.254.169.254/latest/meta-data/` or `http://10.20.10.11/`. | Harvester raises `SecuritySSRFBlockedException` before opening socket. |
| **ACC-09** | Redirect SSRF Filter | Harvester supplied public URL that issues HTTP 302 redirect to `http://127.0.0.1:8080/`. | Redirect target IP is pre-resolved and blocked with `SecuritySSRFBlockedException`. |
| **ACC-10** | Idempotent Ingestion | Same CSAF document ingested twice in succession. | Database row count remains identical; zero duplicate rules or findings created. |
| **ACC-11** | Decompression Safety | Malformed archive containing relative path `../../etc/shadow` or zip bomb. | Extractor aborts with `SecurityPathTraversalException` and archives to quarantine. |
| **ACC-12** | Complete Air-Gap Test | Matcher executed with all network sockets intercepted and disabled. | Matcher runs to completion using local SQLite with zero socket errors. |
| **ACC-13** | Database WAL Snapshot | Live database backed up using SQLite Online Backup API during active WAL. | Snapshot passes `PRAGMA integrity_check` and imports cleanly on destination node. |
| **ACC-14** | Analyst Review Staling | Analyst confirms match for Rule Hash `A`. Advisory update changes rule to Hash `B`. | Analyst review row is automatically marked `is_stale = 1`. |
| **ACC-15** | Backward-Compatibility | Legacy report module calls `lookup_cves_for_assets(assets)` adapter. | Adapter returns structured list compatible with report rendering without exceptions. |
