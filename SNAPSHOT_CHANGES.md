# Snapshot Changes & Sanitization Log

**Document Version**: 1.0.0  
**Snapshot Target**: `IndusProbe-public-review`  
**Reference Source**: `/Users/tejas/Documents/chaitanya/ICS/IndusProbe`  
**Date**: 2026-11-11  

---

## 1. Excluded Files & Categories

The following files and directories from the local development environment were **strictly excluded** from this public review snapshot:

| Category | Excluded Path / Pattern | Reason for Exclusion |
|---|---|---|
| **Customer Reports** | `reports/IndusProbe_UltraTech_Cement_Works_—_Line_2_20261105.*` | Contains real customer company name ("UltraTech") and facility location details. Excluded to prevent client data exposure. |
| **Copyrighted Standard Text** | `docs/is16335:2015.md` | Contains substantial reproduced text of Indian Standard IS 16335:2015 (Bureau of Indian Standards copyright). Excluded due to uncertain redistribution permission. |
| **Dormant External Clones** | `external_repos/` (`profinet`, `pycomm3`, `pylogix`, `zeek-plugin-profinet`) | Inactive, third-party cloned repositories containing active transmission tools (pylogix PLC writes, raw Ethernet DCP frames) and unlicensed code (devkid/profinet). Not imported by IndusProbe. |
| **Binary PDF Reports** | `reports/*.pdf` (e.g. `IndusProbe_DEMO_...pdf`, `IndusProbe_Testbed_...pdf`) | Large compiled binary artifacts (500 KB to 1.2 MB each). HTML and Markdown equivalents are provided in `sample_reports/`. |
| **Databases & Runtime State** | `data/` (`advisories.db`, `advisories.db-wal`, `advisories.db-shm`, `data/archive/`) | Local SQLite database files and raw archive cache. The test suite operates on ephemeral in-memory/temp databases. |
| **Virtual Environments** | `.venv/` | Python runtime environment, system site-packages, and local symlinks. |
| **Build & Cache Artifacts** | `indus_probe.egg-info/`, `__pycache__/`, `*.pyc`, `.pytest_cache/` | Ephemeral build metadata and bytecode. |
| **OS Metadata Files** | `.DS_Store`, `._*` | macOS filesystem metadata. |
| **Temporary Staging Directories** | `for chatgpt/` | Ad-hoc local staging directory containing duplicate code files. |
| **Empty Directories** | `templates/` | Empty folder in source repository. |

---

## 2. Sanitized Files

Only one source file required modification to eliminate developer-specific absolute paths without altering analytical behavior:

### `generate_cement_report.py`
- **Location**: Line 364
- **Original Code**:
  ```python
  output_dir = Path("/Users/tejas/Documents/chaitanya/ICS/IndusProbe/reports")
  ```
- **Sanitized Review Code**:
  ```python
  output_dir = Path("./reports")
  ```
- **Rationale**: Replaces local macOS user directory path with a portable relative directory (`./reports`), enabling the demonstration script to execute out-of-the-box on any reviewer's workstation.
- **Behavioral Impact**: Reports are written to `./reports` in the working directory rather than failing on machines lacking `/Users/tejas/`.

---

## 3. Structural Reorganization for Review

To make the codebase accessible and navigable for independent reviewers, documentation and evidence files were organized into standard directories:

| Original Source Location | Review Snapshot Location | Description |
|---|---|---|
| Root markdown/CSV files (`acceptance_tests.md`, `data_model.md`, `actual_usage_map.md`, `licence_review_register.csv`, etc.) | `docs/` | Grouped into a dedicated `docs/` folder to separate documentation from package root. |
| `reports/IndusProbe_Demonstration_Cement_Plant_...html/.md` | `sample_reports/` | Preserved as the single canonical synthetic demonstration report. |
| `REVIEW_PACKAGE/execution_evidence/*` | `review_evidence/` | Grouped all test logs, smoke test results, and source verification evidence. |

---

## 4. Replacement Synthetic Data

- **No proprietary or plant data is present in this snapshot**.
- All sample reports, PCAP descriptions, and asset registers included in `sample_reports/` and `tests/fixtures/` are **explicitly labeled synthetic fixtures** (e.g. `Demonstration Cement Plant — Clinker Line 2`, `sample_inventory.json`).
- These fixtures exercise parser logic and test assertions without exposing live plant configurations.

