# IndusProbe Advisory Intelligence & Evidence-Based CVE Matcher
## Implementation Plan (Discovery, Architecture & Execution Strategy)

**Document Version:** 1.1.0-REVISED-PROPOSAL  
**Date:** 2026-11-10  
**Target Module:** `indus_probe.advisory` (Standalone / Decoupled)  
**Python Compatibility:** Python >= 3.9 (Preserving package baseline without elevation)  
**Status:** PROPOSED — PENDING ARCHITECTURAL APPROVAL (DO NOT CODE YET)  

---

## 1. Executive Summary & Revised MVP Scope

IndusProbe is an industrial passive network assessment platform serving operational technology (OT) environments across cement, metals, mining, chemicals, and pharmaceuticals.

### 1.1 Reduced MVP Boundary (Phase 1)
To eliminate false conclusions while maintaining safety and tight focus, the initial MVP scope is strictly reduced:
- **Target Vendors**: **Schneider Electric** and **Rockwell Automation** ONLY.
- **Advisory Volume**: Bounded sample of 5–10 authoritative advisories per vendor (subject to verified access).
- **Vulnerability Data**: Associated official CVE records from the official `CVEProject/cvelistV5` repository and CISA KEV status.
- **Storage**: Local embedded SQLite 3 database (`advisories.db`) with Write-Ahead Logging (WAL).
- **Interface**: Standalone CLI (`indus-advisory`) generating structured JSON, analyst review CSV, and standalone HTML summary.
- **Decoupling**: **Zero modification** to existing production report generation (`indus_probe/report.py`) or PCAP capture routines until the standalone module is independently reviewed and accepted.
- **Explicit Exclusions**: No Siemens ingestion in Phase 1; no dashboard; no cloud services; no vector databases; no active network probes.

---

## 2. Benchmark Regression Analysis (Ground-Truth Evidence)

All assumptions from conversation history were discarded. The official records for the three benchmark CVEs were retrieved, SHA-256 hashed, and analyzed from authoritative sources (`CVEProject/cvelistV5`, Schneider Electric CSAF repository, and CISA CSAF repository).

### 2.1 Critical Correction: `CVE-2020-7537`
* **Previous Erroneous Assumption**: Claimed that Modicon M580 was unaffected and asserted that an M580 asset must return `NO_APPLICABLE_RULE_FOUND`.
* **Authoritative Record**: Schneider Electric CSAF advisory `SEVD-2020-343-08` and `CVE-2020-7537.json` explicitly list **Modicon M580 CPUs (prior to version 3.20)** as **`known_affected`** (Product ID `1`).
* **Corrected Rule**:
  - An M580 controller with unknown firmware version MUST evaluate to **`PRODUCT_MATCH_VERSION_UNKNOWN`** (Candidate advisory; version verification required).
  - It must **NEVER** be declared unaffected.
  - It must **NEVER** be declared affected without firmware evidence.
  - If firmware is verified as `< 3.20`, it evaluates to **`AFFECTED_PER_ADVISORY`**.
  - If firmware is verified as `>= 3.20`, it evaluates to **`NOT_AFFECTED_PER_ADVISORY`**.

### 2.2 Authoritative Regression Benchmark Matrix

| CVE ID | Authoritative Source Artifact & SHA-256 | Source Locator | Asset Facts Evaluated | Expected Outcome | Technical Reasoning | Missing Evidence / Scope Limitation |
|---|---|---|---|---|---|---|
| **CVE-2020-7537** | `sevd-2020-343-08.json`<br>`SHA256: 8590e455...` | `/vulnerabilities/0/product_status/known_affected` (Product ID `1`) | Vendor: Schneider<br>Model: Modicon M580<br>Firmware: *Unknown* | **`PRODUCT_MATCH_VERSION_UNKNOWN`** | Hardware model matches affected product line (M580 CPUs `BMEx58xxxxx`). Advisory affects versions `< 3.20`. Because firmware is unobserved, outcome remains a candidate. | Firmware version missing from passive trace. Negative result does not imply controller is secure. |
| **CVE-2020-7537** | `sevd-2020-343-08.json`<br>`SHA256: 8590e455...` | `/vulnerabilities/0/product_status/known_affected` (Product ID `2`) | Vendor: Schneider<br>Model: Modicon M340<br>Firmware: `BMXP34 SV3.20` | **`AFFECTED_PER_ADVISORY`** | Model matches M340 CPUs (`BMX P34x`). Verified firmware `SV3.20` is strictly less than patched version `3.30`. | None. Both model and firmware version are verified against advisory. Exploitation not tested. |
| **CVE-2020-7537** | `sevd-2020-343-08.json`<br>`SHA256: 8590e455...` | `/product_tree/branches/0/branches` | Vendor: Schneider<br>Model: Altivar ATV930 Drive<br>Firmware: `v1.8` | **`NO_APPLICABLE_RULE_FOUND`** | Altivar process drives are variable speed motor drives, not programmable logic controllers (PLCs), and do not run Modicon CPU firmware. | None. Device model is explicitly outside the advisory product tree. |
| **CVE-2021-22779** | `sevd-2021-194-01.json`<br>`SHA256: b5e3a325...` | `/vulnerabilities/0/product_status/known_affected` (Product ID `3`) | Vendor: Schneider<br>Model: Engineering Workstation<br>Software: EcoStruxure Control Expert `v14.1` | **`AFFECTED_PER_ADVISORY`** | Product matches EcoStruxure Control Expert. Installed version `v14.1` is strictly prior to patched version `15.0 SP1`. | None. Software application and version match advisory assertions. |
| **CVE-2021-22779** | `sevd-2021-194-01.json`<br>`SHA256: b5e3a325...` | `/vulnerabilities/0/product_status/known_affected` (Product ID `8`) | Vendor: Schneider<br>Model: Modicon M580 ePAC<br>Firmware: *Unknown* | **`PRODUCT_MATCH_VERSION_UNKNOWN`** | Hardware model matches affected M580 CPU line. Because firmware is unknown, outcome remains candidate pending version walkdown. | Controller firmware revision unverified in packet capture. |
| **CVE-2018-10620** | `CVE-2018-10620.json`<br>`SHA256: ec542cec...` | `/containers/cna/affected/0` (AVEVA) | Vendor: Yokogawa<br>Model: CENTUM VP Gateway<br>Firmware: `R6.03` | **`NO_APPLICABLE_RULE_FOUND`** | CVE-2018-10620 is an AVEVA InduSoft Web Studio / InTouch Machine Edition buffer overflow. It has zero applicability to Yokogawa hardware. | None. Manufacturer and product family are completely unrelated. |

*Critical Principle*: A negative match (`NO_APPLICABLE_RULE_FOUND` or `NOT_AFFECTED_PER_ADVISORY`) for a specific CVE applies **only** to that evaluated advisory. It is **never** presented as an overall clean bill of health or general assurance of security.

---

## 3. Architecture & Data Flow

```
                        [ AIR-GAPPED BOUNDARY: PREPARATION vs RUNTIME ]
┌───────────────────────────────────────┐          ┌───────────────────────────────────────┐
│     Verified Vendor CSAF Sources      │          │     Local Field / Assessment Node     │
│  - Schneider CSAF Directory           │          │                                       │
│  - CISA ICS CSAF Repository (Rockwell)│          │  ┌─────────────────────────────────┐  │
│  - Official CVEProject/cvelistV5      │          │  │ Bounded Evidence-Backed Asset   │  │
└───────────────────┬───────────────────┘          │  │ Inventory (JSON / CSV)          │  │
                    │                              │  └────────────────┬────────────────┘  │
                    ▼                              │                   │                   │
┌───────────────────────────────────────┐          │                   ▼                   │
│      SSRF-Guarded Harvester           │          │  ┌─────────────────────────────────┐  │
│  - Pre-fetch DNS IP sanitization      │          │  │  Deterministic Matching Engine  │  │
│  - Strict redirect validation         │          │  │  - 3-Valued Logic (T / F / UNK) │  │
│  - Internal client throttling (2 rps) │          │  │  - Custom OT Version Comparator │  │
└───────────────────┬───────────────────┘          │  │  - Categorical Outcome States   │  │
                    ▼                              │  └────────────────┬────────────────┘  │
┌───────────────────────────────────────┐          │                   │                   │
│   Immutable Raw Archive (Content-Add.)│          │                   ▼                   │
│   /data/advisories/archive/<sha256>   │          │  ┌─────────────────────────────────┐  │
└───────────────────┬───────────────────┘          │  │     Output Generation           │  │
                    ▼                              │  │  - Match Results JSON           │  │
┌───────────────────────────────────────┐          │  │  - Analyst Review Queue CSV     │  │
│ Normalized SQLite DB (advisories.db)  │          │  │  - Standalone HTML Summary      │  │
│ (Online Backup API -> Snapshot)       │─────────►│  └─────────────────────────────────┘  │
└───────────────────────────────────────┘          └───────────────────────────────────────┘
                     Portable Offline Bundle
                     (.tar.gz + SHA256 manifest)
```

---

## 4. Rigorous OT Version Handling

`packaging.version` (PEP 440) is explicitly rejected as a universal OT comparator. OT firmware utilizes heterogeneous, non-semantic conventions across vendors.

### 4.1 Comparison Rules by Vendor & Product Family
1. **Raw String Preservation**: The raw version string as observed on the wire or read from an advisory is stored unmodified in `raw_version_string`.
2. **Schneider Electric Modicon & Software (`SCHNEIDER_OT`)**:
   - Firmware prefix stripping: `SV3.20` -> major `3`, minor `20`.
   - Software service packs: `15.0 SP1` -> tuple `(15, 0, 1, 0)`.
   - Ordering rule: `SV3.20 < SV3.30 < SV4.10`.
   - `14.1 < 15.0 < 15.0 SP1 < 15.1`.
3. **Rockwell Automation Logix (`ROCKWELL_LOGIX`)**:
   - Format: `vXX.YYY` (e.g. `v33.011`, `v32.014`).
   - Normalization: Leading `v` stripped; dot-separated integers compared numerically: `(33, 11) > (33, 10)`.
   - Leading zeros: `01` is evaluated numerically as `1`.
4. **Hardware Series Constraints**:
   - Hardware series (e.g., `Series A`, `Series B`) are evaluated as strict categorical prerequisites before version numerical comparison is attempted. A firmware match on `Series B` does not trigger a rule bound strictly to `Series A`.
5. **Fallback & Ambiguity**:
   - If a version string does not conform to the registered scheme, or if vendor ordering rules are ambiguous, the comparator returns **`UNKNOWN`**. Ambiguous versions are never coerced into semantic versioning.

---

## 5. Offline Bundle Creation & Atomic Deployment

To guarantee that WAL state, concurrent reads, and file integrity are preserved without file corruption:
1. **Consistent Snapshotting**: The SQLite database snapshot is generated using SQLite's native Online Backup API (`VACUUM INTO 'snapshot.db'` or Python `sqlite3.Connection.backup()`). Raw filesystem copying of `advisories.db` while `advisories.db-wal` exists is strictly prohibited.
2. **Bundle Packaging**:
   - Artifacts packaged into `indusprobe-advisory-bundle-<timestamp>.tar.gz`:
     - `advisories.db` (consistent snapshot)
     - `manifest.json` (SHA-256 of database, schema version, export timestamp, ruleset hash)
     - `raw_archive/` (minimal SHA-256 raw JSON files verifying ingested rules)
3. **Integrity & Verification**:
   - Upon import on the target air-gapped node, the tool computes the SHA-256 hash of `advisories.db` and validates it against `manifest.json`.
   - Runs `PRAGMA integrity_check` on the database before activation.
4. **Atomic Activation & Rollback**:
   - Active database is accessed via a symlink `data/advisories/active.db`.
   - Updating points the symlink atomically to the new verified database.
   - If any validation check fails, the symlink remains pointed to the previous database version (instant rollback).
5. **Trust Limitation**:
   - Checksums guarantee transmission integrity, not publisher identity. Cryptographic publisher authenticity is validated via vendor OpenPGP keys during online ingestion before bundle packaging.

---

## 6. Safety, Compatibility & Git Isolation

1. **Python Compatibility**:
   - All code is implemented to support **Python >= 3.9** natively. Type annotations use standard `typing` constructs (`Optional`, `Union`, `Dict`, `List`, `Tuple`) and `from __future__ import annotations`. The Python baseline will not be raised.
2. **Pre-Git Safety Procedure**:
   Before initializing a Git repository:
   - A full external filesystem backup of `/Users/tejas/Documents/chaitanya/ICS/IndusProbe` will be created at `/Users/tejas/Documents/chaitanya/ICS/IndusProbe_backup_<timestamp>`.
   - A strict `.gitignore` will be deployed before running `git add`:
     ```gitignore
     # Virtual environments
     .venv/
     venv/
     ENV/

     # Python artifacts & caches
     __pycache__/
     *.py[cod]
     *.egg-info/
     dist/
     build/

     # Sensitive OT assessment data & PCAPs
     *.pcap
     *.pcapng
     *.cap
     client_inventories/
     reports/*.pdf
     reports/*.html
     reports/*.md
     !reports/.gitkeep

     # Raw advisory caches & databases
     data/advisories/archive/
     data/advisories/*.db
     data/advisories/*.db-wal
     data/advisories/*.db-shm
     *.tar.gz

     # Secrets and environment configs
     *.env
     *.key
     *.pem
     .DS_Store
     ```

---

## 7. Storage, Memory & Performance Estimates (Unmeasured Estimates)

> **Notice**: All numbers below are **unmeasured engineering estimates** based on data structures. No performance benchmarks have been executed yet. A formal benchmarking procedure will be executed during Stage 5 testing.

| Metric | Bounded MVP Scope (Schneider + Rockwell) | Basis of Estimate |
|---|---|---|
| Raw Artifact Storage | ~15 – 25 MB | ~15 CSAF JSON files + CVE JSON files (~1.5 MB/advisory) |
| SQLite Database Size | ~8 – 15 MB | ~250 normalized table rows with indexes in WAL mode |
| Matcher Memory Profile | ~30 – 50 MB RAM | In-memory evaluation of small synthetic inventory against rule set |
| Matcher Execution Time | Unmeasured estimate (< 1.5s) | To be formally benchmarked with `pytest-benchmark` |
| Portable Bundle Archive | ~5 – 8 MB compressed | Gzip compressed tarball of database snapshot + manifest |
