# Actual Usage Map & Dependency Traceability Report

**Audit Target**: `IndusProbe` and associated cloned repositories in `/Users/tejas/Documents/chaitanya/ICS/`  
**Audit Mode**: Read-Only Passive Safety Audit  
**Date**: 2026-11-10  

---

## 1. Executive Summary

This usage map traces all direct and indirect interactions between the `IndusProbe` codebase and the 19 external repositories residing on the local filesystem.

**Key Finding**:  
**None of the 19 cloned repositories are imported as Python modules or invoked as subprocesses by the core IndusProbe package.**  
- The 4 repositories located in `IndusProbe/external_repos/` (`profinet`, `pycomm3`, `pylogix`, `zeek-plugin-profinet`) are **100% dormant / unlinked**.
- Code inside `IndusProbe/indus_probe/protocols/profinet.py` is a lightweight passive dissector written with standard Python `struct`, which does not import or call `external_repos/profinet` or `zeek-plugin-profinet`. External clones are excluded; complete historical code provenance and license obligations have not been independently verified.
- The only functional cross-repository links are:
  1. A file-path reference to PCAP sample files located in `industrial-scanner/pcaps/` by the test runner `indus_probe/otforge_test.py`.
  2. Data format compatibility mapping in `indus_probe/onealert_bridge.py` generating JSON/JSONL aligned with OneAlert's schema (without importing OneAlert code).
  3. Narrative references in `README.md` and CLI report labels citing `otforge`, `ICS-Cybersecurity-Audit`, and `ics-iot-ot-hardening`.

---

## 2. Granular Usage Traceability

### 2.1 `industrial-scanner` (Remote: `https://github.com/frangelbarrera/industrial-scanner`)
* **Checked-out Commit**: `ff2e2be0aa16d84912b0960b5377c608e4618829`
* **Licence**: MIT License (2025 Frangel Raúl Crespo Barrera)
* **Usage Category**: **Test / PCAP Asset Provider (Read-Only File Access)**
* **Traceability**:
  - `indus_probe/otforge_test.py:21`:
    ```python
    default_pcap = Path("/Users/tejas/Documents/chaitanya/ICS/industrial-scanner/pcaps/s7/step7_s300_stop.pcapng")
    ```
  - `indus_probe/otforge_test.py:23`:
    ```python
    default_pcap = Path("/Users/tejas/Documents/chaitanya/ICS/industrial-scanner/pcaps/dnp3/read_and_response.pcap")
    ```
  - `README.md:87`:
    ```markdown
    | `industrial-scanner` | Protocol parsers reused |
    ```
* **Code Provenance & Verification**:
  - *Claim in README*: "Protocol parsers reused".
  - *Verification*: Detailed comparison between `industrial-scanner/s7_comm_analyzer/parsers.py` (307 lines) and `indus_probe/protocols/detector.py` (`_parse_s7`, lines 123–162) reveals that IndusProbe implements its own minimal 40-line TPKT/COTP/S7 header dissector using pure Python slice unpacking. The 300-line scapy-based S7 parameter block parser from `industrial-scanner` was **NOT** imported or copied verbatim. The origin of protocol constants is standard S7 specification (RFC 1006 / Wireshark dissector packet-s7comm.c).
  - *Uncertainty Status*: **Verified Separate Implementation** (only PCAPs are referenced).

---

### 2.2 `OneAlert` (Remote: `https://github.com/mangod12/OneAlert`)
* **Checked-out Commit**: `4f04de556d88f33dba40668e97640377ddf8b961`
* **Licence**: MIT License (2026 Anshaj Kumar)
* **Usage Category**: **Alert Ingestion Target / Data Output Format Alignment**
* **Traceability**:
  - `indus_probe/onealert_bridge.py:2-12`:
    ```python
    """
    IndusProbe — OneAlert SOC Bridge
    Exports IndusProbe passive findings, detected assets, and protocol events
    into OneAlert / Suricata EVE compatible JSON formats...
    """
    ```
  - `indus_probe/onealert_bridge.py:14-162`: `export_to_onealert(assets, sessions, findings, output_dir)`
  - `indus_probe/cli.py:99-114`:
    ```python
    from indus_probe.onealert_bridge import export_to_onealert
    onealert_files = export_to_onealert(...)
    ```
  - `README.md:91`:
    ```markdown
    | `OneAlert` | Forward findings to OneAlert SOC |
    ```
* **Code Provenance & Verification**:
  - *Verification*: `onealert_bridge.py` does not import any module from `OneAlert/backend/` or `OneAlert/frontend/`. It independently formats local dictionary data into standard Suricata EVE JSON (`event_type: "alert"`) and a generic JSON asset list.
  - *Execution*: Generates local files `onealert_eve_events.jsonl` and `onealert_assets.json`. Zero network transmission, zero socket connections, zero RPC to OneAlert backend.
  - *Uncertainty Status*: **Verified Decoupled Formatter**.

---

### 2.3 `otforge` (Remote: `https://github.com/iburres/otforge`)
* **Checked-out Commit**: `e87fe3d51a12adbdc2dc6958bed5b2a6e96a472d`
* **Licence**: MIT License (2026 Ian Burres)
* **Usage Category**: **Documentation / Reference (String Label Only)**
* **Traceability**:
  - `indus_probe/otforge_test.py:1-40`: Test runner file named `otforge_test.py`, but containing zero imports or calls to `otforge`.
  - `indus_probe/cli.py:287`:
    ```python
    site="Virtual OT Environment (otforge / S7)"
    ```
  - `README.md:92`:
    ```markdown
    | `otforge` | Test IndusProbe against virtual PLC lab |
    ```
  - Generated reports (`reports/IndusProbe_Testbed_Lab_Assessment_20261105.html:101`, `.md:6`):
    ```markdown
    | **Site** | Virtual OT Environment (otforge / S7) |
    ```
* **Code Provenance & Verification**:
  - *Verification*: Zero lines of code from `otforge` (a scapy-based packet generator) are integrated or executed. The name is used exclusively as a text descriptor for a synthetic virtual lab testbed.
  - *Uncertainty Status*: **Verified Unused (Nominal Reference Only)**.

---

### 2.4 `IndusProbe/external_repos/profinet` (Remote: `https://github.com/devkid/profinet.git`)
* **Checked-out Commit**: `ffaae64ad43323f9820cccc38523529b31347f72`
* **Licence**: **NONE (Unlicensed repository by devkid)**
* **Usage Category**: **Unused (Dormant Clone)**
* **Traceability**:
  - `IndusProbe/external_repos/profinet`: Cloned locally under `IndusProbe/external_repos/`.
  - *In-tree search*: Zero imports, zero references in `sys.path`, zero subprocess calls.
* **Code Provenance & Verification**:
  - `external_repos/profinet/` contains an active PROFINET DCP client (`dcp.py`, `protocol.py`, `rpc.py`) with raw Ethernet frame transmission (`s.send(bytes(eth))`) and station configuration functions (`set_param`).
  - `indus_probe/protocols/profinet.py` was authored separately as a passive dissector. It does not import `util`, `protocol`, or `dcp` from `external_repos/profinet`.
  - *Uncertainty Status*: **Verified Unused**.

---

### 2.5 `IndusProbe/external_repos/pylogix` (Remote: `https://github.com/dmroeder/pylogix.git`)
* **Checked-out Commit**: `193b6c7b0c601619223ee53587abd821d3b344c1`
* **Licence**: Apache License 2.0
* **Usage Category**: **Unused (Dormant Clone)**
* **Traceability**:
  - `IndusProbe/external_repos/pylogix`: Cloned locally under `IndusProbe/external_repos/`.
  - *In-tree search*: Zero imports, zero calls.
* **Code Provenance & Verification**:
  - `pylogix` is an active read/write client for Rockwell ControlLogix/CompactLogix PLCs.
  - No IndusProbe component imports `pylogix.PLC`. EtherNet/IP parsing in `indus_probe/protocols/detector.py:165-195` is an independent 30-line passive header decoder.
  - *Uncertainty Status*: **Verified Unused**.

---

### 2.6 `IndusProbe/external_repos/pycomm3` (Remote: `https://github.com/ottowillems/pycomm3.git`)
* **Checked-out Commit**: `NO_COMMIT` (Empty git directory)
* **Licence**: Unspecified at current checkout (empty tree)
* **Usage Category**: **Unused (Empty Directory)**
* **Traceability**:
  - Only `.git` folder exists; no source tree checked out.
  - *Uncertainty Status*: **Verified Unused**.

---

### 2.7 `IndusProbe/external_repos/zeek-plugin-profinet` (Remote: `https://github.com/amzn/zeek-plugin-profinet.git`)
* **Checked-out Commit**: `977f8be907d648d8bb45c9d3dd2aa1701c3cfa5d`
* **Licence**: Custom 3-Clause BSD-style License (Amazon.com, Inc.)
* **Usage Category**: **Unused (Dormant C++/BinPAC Plugin)**
* **Traceability**:
  - Contains C++ and BinPAC source files (`src/PROFINET.cc`, `src/profinet-protocol.pac`).
  - Not compiled, not linked, not loaded by Zeek.
  - *Uncertainty Status*: **Verified Unused**.

---

### 2.8 Narrative-Only / Reference Repositories
The following 12 repositories are present on the local machine under `/Users/tejas/Documents/chaitanya/ICS/` but have **zero code integration, zero imports, and zero subprocess execution** within `IndusProbe`:

| Repository | Local Path | Licence | Status in IndusProbe |
|---|---|---|---|
| `EmbedXPL-Forge` | `EmbedXPL-Forge` | BSD-3-Clause | **Unused** (Embedded exploitation toolkit; zero links) |
| `GasPot` | `GasPot` | CC BY-NC-SA 4.0 | **Unused** (ATG honeypot; zero links) |
| `ICS-Cybersecurity-Audit` | `ICS-Cybersecurity-Audit` | MIT | **Reference only** (Cited in README.md as framework inspiration) |
| `ICS-Security-Tools` | `ICS-Security-Tools` | CC BY 4.0 | **Unused** (Zero links) |
| `Industrial-Cybersecurity-2nd-Edition` | `Industrial-Cybersecurity-2nd-Edition` | GPL-3.0 | **Reference only** (Book companion files; zero links) |
| `LICSTER` | `LICSTER` | MIT + GPLv3 / ST | **Unused** (Hardware testbed code; zero links) |
| `OT_Security_OnePagers` | `OT_Security_OnePagers` | CC BY 4.0 | **Reference only** (Cited in README.md; zero links) |
| `awesome-industrial-control-system-security` | `awesome-...` | Apache-2.0 | **Documentation only** (Curated list; zero links) |
| `awesome-ot-security` | `awesome-...` | CC BY-SA 4.0 | **Documentation only** (Curated list; zero links) |
| `conpot` | `conpot` | GPL-2.0 | **Unused** (ICS honeypot; zero links) |
| `ics-iot-ot-hardening` | `ics-iot-ot-hardening` | MIT | **Reference only** (Cited in README.md; zero links) |
| `labshock` | `labshock` | Proprietary v2.0 / GPLv3 | **Unused** (Commercial virtualization; zero links) |

