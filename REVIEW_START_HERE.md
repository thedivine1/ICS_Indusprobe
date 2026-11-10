# IndusProbe — Review Snapshot & Architecture Guide

**Snapshot Date**: 2026-11-11  
**Repository**: `https://github.com/thedivine1/ICS_Indusprobe.git`  
**Target Audience**: Independent OT Cybersecurity Reviewers, Automation Engineers, Security Auditors  

---

## 1. What the Project Does

IndusProbe is a passive operational technology (OT) cybersecurity assessment and asset discovery engine designed for industrial control system (ICS) environments (cement, metals, mining, chemicals, pharmaceuticals).

The engine operates on network packet captures (PCAP/PCAPNG) or listen-only network SPAN/mirror ports to:
1. Passively identify industrial devices, controllers, remote I/O, HMIs, and engineering workstations from protocol payload signatures (Modbus TCP, Siemens S7Comm, EtherNet/IP, DNP3, HART-IP, OPC UA, PROFINET).
2. Detect command and parameter write operations on industrial conduits without active polling.
3. Evaluate network traffic against security requirements of **IEC 62443-3-3** (Foundational Requirements FR 1 to FR 7).
4. Cross-reference discovered assets against authoritative vendor security advisories and CVEs using an evidence-based matching engine (`indus_probe.advisory`).

---

## 2. Intended First Pilot Scope

- **Deployment Profile**: Passive field drop-box sensor (Raspberry Pi 4/5 or fanless industrial Box PC) connected to a plant switch SPAN/mirror port or network TAP.
- **Initial Target Verticals**: Cement manufacturing (clinker lines, raw mills), pharmaceuticals (batch packaging lines).
- **Target Vendor Priority**:
  - **P1**: Schneider Electric (Modicon M580, M340, Quantum) and Rockwell Automation (ControlLogix, CompactLogix).
  - **P2**: Siemens (SIMATIC S7-300, S7-1200, S7-1500) and Yokogawa (CENTUM VP).
- **Operational Boundaries**: Pure listen-only inspection. Zero active probing, zero credential brute-forcing, zero packet injection.

---

## 3. Project Tree (Review Snapshot)

```
IndusProbe-public-review/
├── README.md                          # Original project README
├── REVIEW_START_HERE.md               # This document (Reviewer guide)
├── SNAPSHOT_CHANGES.md                # Changes, sanitization & omissions log
├── requirements.txt                   # Declared Python dependencies
├── setup.py                           # Package configuration (indus-probe, indus-advisory CLI)
├── .gitignore                         # Build, cache, database, and PCAP exclusions
├── generate_cement_report.py          # Synthetic cement plant demonstration dataset generator
├── indus_probe/                       # Core Python package
│   ├── __init__.py
│   ├── capture.py                     # Passive PCAP/Live packet analyzer (pyshark / scapy)
│   ├── cli.py                         # CLI entry points (demo, pcap, sensor, lab)
│   ├── cve_lookup.py                  # Legacy static CVE reference table
│   ├── diagram.py                     # Plant architecture diagram generation (Mermaid/PlantUML)
│   ├── fingerprint.py                 # OUI and MAC vendor lookup
│   ├── iec62443.py                    # IEC 62443-3-3 rule evaluation engine
│   ├── onealert_bridge.py             # Formatter for Suricata EVE JSON / OneAlert schema
│   ├── otforge_test.py                # Lab automated PCAP test runner (references dev pcaps)
│   ├── pharma_cfr11.py                # FDA 21 CFR Part 11 audit rule checks
│   ├── report.py                      # Markdown, HTML, and headless Chrome PDF generator
│   ├── sensor.py                      # Field drop-box sensor daemon (listen-only interface configuration)
│   ├── advisory/                      # Evidence-based advisory intelligence & CVE matcher module
│   │   ├── __init__.py
│   │   ├── adapter.py                 # Backward-compatibility drop-in adapter (inactive in report.py)
│   │   ├── archive.py                 # Immutable content-addressed SHA-256 raw advisory archive
│   │   ├── cli.py                     # Standalone CLI (indus-advisory: verify-db, ingest, match, export-bundle)
│   │   ├── db.py                      # SQLite WAL schema (10 tables, migrations, FK checks)
│   │   ├── exporter.py                # Standalone HTML, JSON, and CSV exporter
│   │   ├── fetcher.py                 # SSRF-guarded HTTP fetcher (2 rps throttle, public IP validation)
│   │   ├── ingestor.py                # Bounded advisory ingestion pipeline (CSAF/JSON)
│   │   ├── matcher.py                 # 3-valued deterministic matching engine (8 categorical states)
│   │   ├── models.py                  # Typed dataclasses (AssetFact, Advisory, AffectedProduct, MatchResult)
│   │   ├── version_engine.py          # Custom OT version comparators (SCHNEIDER_OT, ROCKWELL_LOGIX)
│   │   └── parsers/
│   │       ├── __init__.py
│   │       ├── csaf.py                # CSAF 2.0 product_tree resolver & bound extractor
│   │       └── cve_json.py            # CVE JSON 5.1 metadata parser
│   └── protocols/                     # Protocol dissectors
│       ├── __init__.py
│       ├── detector.py                # Fast port mapping & protocol identification
│       ├── hart.py                    # HART-IP UDP/TCP 5094 dissector
│       ├── opc_ua.py                  # OPC UA TCP binary & SecurityPolicy dissector
│       └── profinet.py                # PROFINET RT / DCP / PROFIsafe Frame ID classifier
├── scripts/
│   └── setup_sensor.sh                # Linux host stealth hardening script (disables ARP, IPv6, flushes IP)
├── tests/
│   ├── test_advisory_matcher.py       # 33 acceptance & regression tests for advisory matcher
│   └── fixtures/
│       ├── sample_inventory.json      # Synthetic 5-asset test inventory
│       └── advisories/
│           ├── sevd-2020-343-08.json  # Labeled synthetic CSAF fixture (Schneider M580/M340 DoS)
│           ├── sevd-2021-194-01.json  # Labeled synthetic CSAF fixture (Schneider Control Expert auth bypass)
│           └── icsa-22-090-05.json    # Labeled synthetic CSAF fixture (Rockwell ControlLogix bytecode)
├── sample_reports/                    # One clearly labeled synthetic demonstration report
│   ├── IndusProbe_Demonstration_Cement_Plant_—_Clinker_Line_2_20261110.html
│   └── IndusProbe_Demonstration_Cement_Plant_—_Clinker_Line_2_20261110.md
├── docs/                              # Architecture, planning, and safety audit documents
│   ├── acceptance_tests.md            # Acceptance test specifications (REG-01 to REG-03, VER-01 to VER-10)
│   ├── data_model.md                  # Complete 10-table SQLite schema DDL specification
│   ├── implementation_plan.md         # Phased implementation strategy
│   ├── source_registry_proposal.yaml  # Verified CSAF endpoints and hashes
│   ├── actual_usage_map.md            # Traceability map of local external repositories
│   ├── external_repository_register.csv # Inventory of 19 cloned repositories
│   ├── licence_review_register.csv    # Licensing and legal compliance register
│   ├── passive_safety_findings.md     # Passive safety and transmission risk findings
│   ├── protocol_capability_matrix.csv # Implemented versus nominal protocol capabilities
│   └── proposed_remediation_plan.md   # 4-phase architectural remediation plan
│                                      # (Note: IS 16335 text excluded due to copyright/redistribution permission)
└── review_evidence/                   # Verification logs from testing and smoke test runs
    ├── SANITIZATION_REPORT.md         # Full sanitization checks and findings
    ├── unittest_execution.txt         # Actual log from 33-test suite run (0.089s offline)
    ├── smoke_test_log.txt             # Trace from advisory matching smoke test run
    ├── smoke_test_results.json        # Machine-readable output from smoke test run
    ├── smoke_test_results.csv         # Analyst review CSV format output
    ├── smoke_test_results.html        # Standalone zero-CDN HTML preview
    ├── source_verification_evidence.md # Verified SHA-256 hashes and HTTP endpoints
    └── FILE_MANIFEST.sha256           # SHA-256 hashes of all snapshot files
```

---

## 4. Declared Runtime Requirements

- **Python Version**: Python >= 3.9 (developed and tested on Python 3.9.6).
- **Core Dependencies**:
  - `pyshark>=0.6.0` (wraps system `tshark` for PCAP dissection)
  - `scapy>=2.5.0` (pure-Python fallback packet parsing)
  - `rich>=13.0.0` (console output formatting)
  - `click>=8.1.0` (CLI interface parsing)
  - `jinja2>=3.1.0` (HTML report templating)
  - `tabulate>=0.9.0` (table rendering in Markdown)
- **Optional System Binaries**:
  - `tshark` / `wireshark`: High-throughput dissection (scapy fallback used if absent).
  - `dumpcap` / `tcpdump`: Dedicated low-overhead capture in sensor daemon.
  - `google-chrome` / `chromium`: Optional for automated HTML-to-PDF export.

---

## 5. Installation Instructions

```bash
# 1. Create a clean Python 3.9+ virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Install IndusProbe in editable review mode
pip install -e .
```

---

## 6. How to Run the Synthetic Demo

```bash
# Generate a complete synthetic cement plant demonstration dataset and report:
python generate_cement_report.py

# Or use the built-in demo subcommand:
indus-probe demo --output ./reports
```

*Expected Output*: Generates `./reports/IndusProbe_Demonstration_Cement_Plant_...html` and `.md`.

---

## 7. How to Run the Tests

```bash
# Run the 33-test acceptance and regression suite (strictly offline, stdlib unittest):
python -m unittest tests.test_advisory_matcher -v
```

*Expected Output*: 33 tests pass in < 0.15s (REG-01 to REG-03, VER-01 to VER-10, ACC-01 to ACC-15).

---

## 8. Network Access & Elevated Privileges Notice

> **CRITICAL OPERATIONAL SAFETY WARNING**  
> **DO NOT EXECUTE `indus-probe sensor` OR `scripts/setup_sensor.sh` CASUALLY ON ANY PRODUCTION INDUSTRIAL NETWORK.**

| Command / Script | Network Activity | Privileges Required | Operational Safety Impact |
|---|---|---|---|
| `indus-probe demo` | **None** (purely in-memory synthetic data) | Standard user | Safe. No sockets created. |
| `indus-probe pcap --file <path>` | **None** (offline file read) | Standard user | Safe. Reads static PCAP file. |
| `indus-advisory match --inventory <path>` | **None** (offline SQLite read) | Standard user | Safe. Local database query. |
| `indus-advisory verify-db` | **None** (local file hash checks) | Standard user | Safe. Local filesystem integrity check. |
| `indus-advisory ingest --url <url>` | **Outbound HTTP GET** | Standard user | Fetches advisory JSON from public vendor URL. Guarded by pre-DNS SSRF blocklist (rejects RFC 1918 / loopback). |
| `indus-probe sensor --interface <iface>` | **Listen-Only Capture** | **Root / `sudo`** | Alters network interface state: flushes IP address, disables ARP, disables IPv6, sets promiscuous mode, invokes `dumpcap`. May disrupt host network connectivity on that interface. |
| `scripts/setup_sensor.sh` | **Listen-Only Hardening** | **Root / `sudo`** | Reconfigures Linux kernel network parameters via `sysctl` and `ip`. Must only be run on dedicated drop-box appliances. |
| `indus-probe lab` | *(Unverified / Developer only)* | Standard user | Fails on clean systems (hardcoded dev paths). See Known Limitations. |

---

## 9. Implemented vs. Unverified Capabilities

| Feature / Protocol | Status in Snapshot | Implementation Reality |
|---|---|---|
| **Modbus TCP** | **Implemented** | Function codes 1–6, 15, 16, 23 dissected; write flags extracted. |
| **Siemens S7Comm** | **Implemented** | TPKT/COTP/S7 header parsing; ROSCTR job/ack classification. Does not parse parameter blocks. |
| **EtherNet/IP** | **Implemented** | Encapsulation header parsing. Does not parse CIP service codes. |
| **DNP3** | **Implemented** | Data link sync (0x0564) and function codes 1–5. No CRC-16 check. |
| **HART-IP** | **Implemented** | Cleartext UDP/TCP 5094 header & pass-through command byte. No DTLS/TLS support. |
| **OPC UA** | **Implemented** | Binary handshake & `SecurityPolicy` extraction. No session token parsing. |
| **PROFINET RT / DCP** | **Partially Implemented** | Frame ID integer range classifier. **Does NOT decode PROFIsafe F-Parameters or CRCs**. Raw Layer 2 frames skipped if using pyshark. |
| **BACnet / IEC-104 / MMS** | **Unverified (Nominal)** | Port mapping only (UDP 47808, TCP 2404, TCP 102). **Zero payload parsing**. |
| **Advisory Intelligence Engine** | **Implemented (Standalone)** | Full SQLite WAL data model, custom OT version comparators (`SCHNEIDER_OT`, `ROCKWELL_LOGIX`), 3-valued deterministic matcher. |
| **Advisory Adapter in Reports** | **Dormant (Unactivated)** | Adapter is implemented in `indus_probe/advisory/adapter.py`, but `indus_probe/report.py` still invokes legacy `cve_lookup.py`. |

---

## 10. Status of Supplied Execution Evidence

- The logs in `review_evidence/` (`unittest_execution.txt`, `smoke_test_log.txt`, `smoke_test_results.json`) represent **existing evidence captured from local offline execution** during preparation.
- **Application source code was NOT executed across production plant networks during snapshot preparation.**
- The smoke tests utilize **synthetic fixtures** and must not be cited as real-world CVE validation.

