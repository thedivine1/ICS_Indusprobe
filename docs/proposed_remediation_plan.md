# Proposed Passive Safety, Supply Chain & Architectural Remediation Plan

**Document Version**: 1.0.0-PROPOSAL  
**Target Project**: IndusProbe  
**Status**: PROPOSED — PENDING ARCHITECTURAL APPROVAL (DO NOT IMPLEMENT CODE CHANGES YET)  
**Date**: 2026-11-10  

---

## 1. Context & Remediation Objectives

This remediation plan addresses the architectural, licensing, and operational risks identified during the read-only external repository usage and passive safety audit.

### Core Objectives:
1. **Total Isolation of Active Tools**: Eliminate dormant active code (`pylogix`, `profinet/dcp.py`) from the sensor codebase.
2. **Strict Production / Synthetic Separation**: Disentangle laboratory test runners, developer file paths, and synthetic disclaimers from live customer plant assessment paths.
3. **Supply Chain & Licensing Hygiene**: Cleanse the repository of unlicensed, copyleft (GPLv2/v3), and non-commercial (CC-BY-NC) contaminants.
4. **Protocol Verification Rigor**: Replace nominal protocol claims with verified, unit-tested dissectors and bounded capture fixtures.

---

## 2. Distinction of Knowledge: Verified Findings vs. Inferences vs. Unresolved Questions

| Category | Item Description | Evidentiary Basis |
|---|---|---|
| **Verified Finding** | `IndusProbe/external_repos/` is completely unreferenced by IndusProbe Python code. | Verified via full AST, regex, and import scan across `indus_probe/`. |
| **Verified Finding** | `sensor.py` and `setup_sensor.sh` enforce true listen-only Linux interface modes (no IP, no ARP, no IPv6). | Code inspection of kernel sysctl and `ip` tool commands in `sensor.py:16-40`. |
| **Verified Finding** | `devkid/profinet` is completely unlicensed (zero license file). | File inspection of `IndusProbe/external_repos/profinet/`. |
| **Verified Finding** | `GasPot` (CC-BY-NC-SA 4.0) and `labshock` (v2.0) explicitly prohibit commercial use. | Direct text review of `GasPot/LICENSE.md` and `labshock/LICENSE`. |
| **Verified Finding** | `report.py` hardcodes "Simulated Unit" and "Synthetic dataset" across all output reports. | Code inspection of `indus_probe/report.py:47, 70, 74-75, 437-438`. |
| **Inference** | Co-location of `external_repos/profinet` may have been intended for active DCP discovery in early prototypes. | Inferred from presence of `profinet/dcp.py` alongside a passive `profinet.py`. |
| **Inference** | `otforge_test.py` was created as an ad-hoc local test script that accidentally remained in the production package. | Inferred from hardcoded macOS absolute paths to `/Users/tejas/...` inside `indus_probe/`. |
| **Unresolved Question** | What is the exact provenance of the PCAPs inside `industrial-scanner/pcaps/`? | The upstream repository does not document whether these captures contain synthetic traffic, testbed recordings, or anonymized customer plant data. |
| **Unresolved Question** | Was `IndusProbe/external_repos/pycomm3` an interrupted clone or intentionally wiped? | Repository contains only a `.git` folder with no commit tree checked out. |

---

## 3. Phased Remediation Workstreams

```
                                [ REMEDIATION ROADMAP ]
┌───────────────────────────────────────┐          ┌───────────────────────────────────────┐
│     Phase 1: Immediate Hygiene        │          │    Phase 2: Architectural Boundary    │
│  - Excise IndusProbe/external_repos/  │          │  - Relocate otforge_test.py to tests/ │
│  - Remove inactive repo subfolders    │ ───────► │  - Separate DEMO vs LIVE report modes │
│  - Cleanse README.md inaccurate claims│          │  - Make OneAlert export opt-in flag   │
└───────────────────────────────────────┘          └───────────────────────────────────────┘
                                                                       │
                                                                       ▼
┌───────────────────────────────────────┐          ┌───────────────────────────────────────┐
│  Phase 4: Protocol Dissection Harness │          │   Phase 3: Cleanroom Licensing Audit  │
│  - Bounded pcap fixtures for HART/OPC │          │  - Formalize open-source NOTICE file  │
│  - True Layer-2 PROFINET dissector    │ ◄─────── │  - Confirm zero GPL/CC-NC in sensor   │
│  - Remove unparsed protocol claims    │          │  - License IndusProbe proprietary core│
└───────────────────────────────────────┘          └───────────────────────────────────────┘
```

---

### Phase 1: Immediate Supply Chain & Repository Hygiene
* **Action 1.1: Delete `IndusProbe/external_repos/`**:
  - Completely remove the `external_repos/` subfolder containing `profinet`, `pycomm3`, `pylogix`, and `zeek-plugin-profinet`.
  - *Safety Impact*: Eliminates any risk of active PLC write drivers or unlicensed code being imported into IndusProbe.
* **Action 1.2: Cleanse `IndusProbe/README.md` Claims**:
  - Remove inaccurate integration claims:
    - Line 87: Change "`industrial-scanner`: Protocol parsers reused" to note that external clones are excluded and parsers require independent provenance audit.
    - Line 92: Remove "`otforge`: Test IndusProbe against virtual PLC lab".
  - Accurately state that IndusProbe uses standalone, passive protocol dissectors.

---

### Phase 2: Architectural Separation (Production Sensor vs. Synthetic Testbed)
* **Action 2.1: Relocate `otforge_test.py` out of Production Module**:
  - Move `indus_probe/otforge_test.py` to `tests/lab_runner.py`.
  - Remove hardcoded absolute paths (`/Users/tejas/Documents/chaitanya/...`).
  - Accept `--pcap` argument or environment variable `INDUS_TEST_PCAP`.
* **Action 2.2: Remove `indus-probe lab` from Production CLI**:
  - Remove the `cmd_lab` function from `indus_probe/cli.py`.
  - Laboratory automated PCAP replaying should be executed via standard test runners (`pytest` / `unittest`), not exposed as a production command on a plant drop-box sensor.
* **Action 2.3: Parameterize Report Generation (`report.py`)**:
  - Introduce an explicit `ReportContext` enumeration:
    - `AssessmentMode.LIVE_PLANT`: Suppresses all "simulated/synthetic" notices; displays plant name, TAP duration, verified asset facts, and formal chain-of-custody metadata.
    - `AssessmentMode.SYNTHETIC_DEMO`: Explicitly labels the report with high-visibility banners: "DEMONSTRATION REPORT — SYNTHETIC TRAFFIC".
  - Ensure real customer reports never label plant controllers as "Simulated Units".
* **Action 2.4: Opt-In OneAlert Bridge Export**:
  - Modify `indus_probe/cli.py` so that `export_to_onealert` runs only when `--export-onealert` is explicitly specified by the operator.
  - Avoids disk sprawl on unattended drop-box SD cards.

---

### Phase 3: Cleanroom Licensing & Intellectual Property Boundaries
* **Action 3.1: Exclude Non-Commercial & Copyleft Tools from Commercial Sensor Builds**:
  - Do not package, distribute, or bundle `GasPot` (CC-BY-NC), `conpot` (GPLv2), `Industrial-Cybersecurity-2nd-Edition` (GPLv3), or `labshock` (Commercial License Required).
  - Treat all `/Users/tejas/Documents/chaitanya/ICS/*` adjacent repositories strictly as external reference documentation.
* **Action 3.2: Formalize Dissector Provenance Audit**:
  - Explicitly document that while `profinet.py`, `hart.py`, `opc_ua.py`, and `detector.py` operate without external imports, complete code provenance, historical source derivation, and license obligations have not been independently verified. Conduct a formal provenance and licensing verification before production release.

---

### Phase 4: Protocol Dissection Verification & Capability Alignment
* **Action 4.1: Downgrade Nominal Protocol Claims**:
  - Remove claims of "BACnet/IP", "IEC 60870-5-104", and "MMS" protocol analysis until actual payload decoders are written. Currently, only port matching exists.
  - Update documentation to state: "BACnet/IP and IEC-104: Port identification only; payload dissection planned for Phase 2".
* **Action 4.2: PROFINET Dissector Realignment**:
  - Explicitly document that IndusProbe's PROFINET engine is a **Frame ID range classifier**, not a complete protocol decoder, and does NOT validate PROFIsafe functional safety logic.
  - Update `capture.py` so that Scapy or raw packet filters can capture Layer-2 EtherType `0x8892` frames without requiring UDP encapsulation.
* **Action 4.3: Build Protocol Unit Test Suite**:
  - Create small, synthetic, hex-encoded packet fixtures in `tests/fixtures/packets/` for Modbus, S7, EtherNet/IP, DNP3, HART-IP, and OPC-UA.
  - Add regression unit tests validating `detect_protocol_from_payload()` and `is_write_command()` for each supported function code.

---

## 4. Remediation Sign-Off Checklist (For Future Action)

- [ ] `IndusProbe/external_repos/` deleted and confirmed removed from git tracking.
- [ ] `otforge_test.py` removed from `indus_probe/` and `setup.py` packages.
- [ ] `report.py` supports separate `LIVE_PLANT` vs `SYNTHETIC_DEMO` modes.
- [ ] `setup_sensor.sh` and `sensor.py` validated as 100% listen-only.
- [ ] Zero GPL-contaminating or CC-BY-NC code linked into `indus_probe`.
- [ ] Protocol capability claims accurately aligned with implemented parsers.

