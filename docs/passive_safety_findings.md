# Passive Safety & Transmission Risk Audit Report

**Auditor Role**: Senior Defensive OT Cybersecurity Engineer  
**Inspection Target**: `IndusProbe` and local clones  
**Status**: READ-ONLY AUDIT COMPLETE  
**Date**: 2026-11-10  

---

## 1. Executive Summary & Core Verdict

IndusProbe's core production runtime (`indus_probe/capture.py`, `indus_probe/sensor.py`, `scripts/setup_sensor.sh`) **strictly complies with the listen-only passive safety model**:
- In sensor drop-box mode, the Linux network interface is explicitly forced into **100% silent promiscuous mode**: IPv6 disabled, ARP disabled, IP address flushed to `0.0.0.0`.
- All packet capture operations rely strictly on `dumpcap`, `tcpdump`, or `pyshark.LiveCapture(interface)`.
- **Zero active probes, zero TCP/UDP packet transmissions, zero discovery broadcasts, and zero active fallback paths** exist in the live capture or PCAP analysis engines.

However, the audit identified **four critical passive safety and isolation risks** that must be remediated before customer-facing production deployment.

---

## 2. Granular Data-Flow & Transmission Risk Analysis

### 2.1 Reachability Matrix: Transmission & Active Operations

| Risk Category | Reachable from IndusProbe Entry Points? | Call Path / Mechanism | Audit Finding & Evidence |
|---|---|---|---|
| **Raw Ethernet Frame Transmission** | **NO (UNREACHABLE)** | None | Present in `external_repos/profinet/dcp.py:33` (`s.send(bytes(eth))`), but `external_repos` is not in `sys.path` and is never imported. |
| **PLC Write / Bytecode Execution** | **NO (UNREACHABLE)** | None | Present in `external_repos/pylogix/` (`PLC().Write`), but neither imported nor invoked anywhere in IndusProbe. |
| **Active Discovery Broadcasts** | **NO (UNREACHABLE)** | None | No ARP, ICMP, SNMP, or UDP broadcast code in `indus_probe/`. `sensor.py` explicitly issues `arp off` and `arp_ignore=8`. |
| **PLC Memory Reads / Active Poll** | **NO (UNREACHABLE)** | None | `_parse_modbus`, `_parse_s7`, `_parse_enip` operate solely on captured bytes (`payload`). No sockets created. |
| **Automatic Active Fallback** | **NO (NONE)** | None | If protocol identification fails, IndusProbe assigns `Protocol.UNKNOWN`. It does NOT attempt an active banner grab or query. |
| **Outbound Telemetry / Cloud APIs** | **NO (NONE)** | None | No references to `requests`, `boto3`, `google.cloud`, `openai`, or `anthropic` in IndusProbe code. |
| **Advisory Fetcher HTTP Requests** | **CONDITIONAL (CLI ONLY)** | `indus-advisory ingest --url` | `indus_probe/advisory/fetcher.py` contains `urllib.request.urlopen`. Restricted strictly to public IPs by SSRF guard. **Unreachable from `indus-probe pcap` or `indus-probe sensor`**. |
| **Local Headless Browser Execution** | **LOCAL PROCESS ONLY** | `report.py:621` | Invokes local `google-chrome --headless=new --print-to-pdf` to convert local HTML to PDF. No external HTTP requests. |
| **Automated Response / Containment** | **NO (DECOUPLED)** | None | `OneAlert/backend/services/agents/response.py` contains automated containment logic, but IndusProbe only outputs static JSON files. |

---

## 3. Passive Safety & Architectural Isolation Findings

### Finding PSF-01: Dormant Active Client Tools Located in Project Tree
* **Severity**: **MEDIUM (Configuration / Supply Chain Risk)**
* **Location**: `IndusProbe/external_repos/profinet/` and `IndusProbe/external_repos/pylogix/`
* **Vulnerability Description**:
  The presence of active PLC write drivers (`pylogix`) and layer-2 Ethernet injection scripts (`profinet/dcp.py` station name/IP changer) directly inside the `IndusProbe` directory structure poses a severe operational hazard. An engineer or junior developer could inadvertently import `from external_repos.pylogix import PLC` or `from external_repos.profinet.dcp import set_param`, transforming a certified passive drop-box sensor into an active transmission hazard on live plant conduits.
* **Call Path**: Currently unreachable, but co-located in project repository.
* **Remediation**: Completely excise `IndusProbe/external_repos/` from the repository and exclude it from packaging.

---

### Finding PSF-02: Lab PCAP Test Runner Packaged into Production Module
* **Severity**: **LOW-MEDIUM (Packaging Boundary Violation)**
* **Location**: `indus_probe/otforge_test.py` and `indus_probe/cli.py:280-291` (`cmd_lab`)
* **Vulnerability Description**:
  The test script `otforge_test.py` hardcodes absolute developer workstation paths:
  - `/Users/tejas/Documents/chaitanya/ICS/industrial-scanner/pcaps/s7/step7_s300_stop.pcapng`
  - `/Users/tejas/Documents/chaitanya/ICS/industrial-scanner/pcaps/dnp3/read_and_response.pcap`
  Because `setup.py` uses `find_packages()`, `otforge_test.py` and the `indus-probe lab` CLI subcommand are bundled into the production installable package. On a customer sensor or field box, running `indus-probe lab` crashes with `FileNotFoundError` due to missing local dev paths.
* **Remediation**: Relocate `otforge_test.py` to `tests/lab_runner.py` and remove `indus-probe lab` from production CLI.

---

### Finding PSF-03: Hardcoded "Demonstrator / Simulated" Disclaimers Across All Reports
* **Severity**: **MEDIUM (Presentation & Operational Integrity Risk)**
* **Location**: `indus_probe/report.py:47, 70, 74-75, 437-438`
* **Vulnerability Description**:
  `report.py` hardcodes the demonstrator notice:
  ```python
  report_version: str = "v1.1-demonstrator"
  "> Findings demonstrate analytical workflows and do not establish real-world asset vulnerabilities."
  "| **Simulated Unit** | {site_location} |"
  "*Notice: Synthetic dataset for technology demonstration purposes only.*"
  ```
  If a passive scan is conducted on a **real, live customer plant** using `indus-probe pcap` or `indus-probe sensor`, the generated report will misleadingly label the customer's actual live findings as "Simulated Unit" and "Synthetic dataset". Conversely, if synthetic data is used, the report does not cryptographically or structurally separate real OUI/pcap evidence from synthetic manifests.
* **Remediation**: Parameterize the report generator with an explicit enum: `AssessmentMode.LIVE_PLANT_PASSIVE` vs `AssessmentMode.SYNTHETIC_DEMONSTRATION`.

---

### Finding PSF-04: Uncontrolled Export to OneAlert SOC Files Without Retention Policy
* **Severity**: **LOW (Data Sprawl / Disk Exhaustion Risk)**
* **Location**: `indus_probe/cli.py:100-114` and `indus_probe/onealert_bridge.py`
* **Vulnerability Description**:
  Every assessment execution unconditionally creates `onealert_eve_events.jsonl` and `onealert_assets.json` in the reports directory. On embedded drop-boxes (Raspberry Pi with SD card), unbounded generation of duplicate JSONL event streams alongside PCAP ring-buffers and HTML reports can cause disk exhaustion.
* **Remediation**: Make OneAlert bridge export an explicit flag (`--export-onealert`) rather than an unconditional default.

---

## 4. Passive Safety Verification Summary

| Check Item | Result | Verification Evidence |
|---|---|---|
| Active IP assignment on capture interface | **PASSED (Blocked)** | `sensor.py:27` issues `ip addr flush dev {iface}` |
| ARP broadcast suppression | **PASSED (Enforced)** | `sensor.py:25-26` sets `arp_ignore=8`, `arp_announce=2`, `arp off` |
| IPv6 solicitation suppression | **PASSED (Enforced)** | `sensor.py:21-23` sets `disable_ipv6=1`, `autoconf=0`, `accept_ra=0` |
| Active protocol polling | **PASSED (Zero code)** | No TCP connect/send calls in `capture.py` or `protocols/` |
| Outbound cloud connections | **PASSED (Zero code)** | No cloud SDKs or outbound telemetries in assessment path |
| Offline matching engine | **PASSED (Verified)** | `indus_probe/advisory/matcher.py` operates strictly on local SQLite |

