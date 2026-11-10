# OT Network Passive Assessment & IEC 62443 Technical Analysis

> ⚠️ **DEMONSTRATION REPORT — SYNTHETIC / LAB-GENERATED TRAFFIC**  
> Fictional cement manufacturing environment. Not an assessment of an actual customer installation.  
> Findings demonstrate analytical workflows and do not establish real-world asset vulnerabilities.

| Metadata Field | Value |
|----------------|-------|
| **Facility / Context** | Demonstration Cement Plant — Clinker Line 2 |
| **Simulated Unit** | Synthetic 5,000 TPD Clinker Line (Demonstration Lab Environment) |
| **Assessment Date** | 2026-11-10 |
| **Capture Telemetry** | 48 Hours Synthetic Baseline Telemetry (2026-11-08 08:00 to 2026-11-10 08:00 IST) |
| **Total Packets Analysed** | 504,010 Ethernet frames |
| **Engine & Author** | IndusProbe Assessment Engine |
| **Reviewer Status** | Draft — Subject to Engineering Review |
| **Document Version** | v1.1-demonstrator |
| **Contact** | `contact@indusprobe.internal` |
| **Classification** | DEMONSTRATION ONLY — Non-Operational Synthetic Data |

---

> **Analytical Methodology**: The assessment component did not initiate active probes. 
> Traffic generation/replay used to construct the lab dataset is documented separately. 
> Zero active packets were transmitted into any operational or simulated OT segment. 
> All technical observations are derived from passive packet header and application payload decoding.

---

## 1. Executive Summary

### Risk Summary

| Severity | Count | Initial Operational Treatment |
|----------|-------|-------------------------------|
| 🔴 CRITICAL | **2** | Urgent validation & containment with plant engineering |
| 🟠 HIGH | **6** | Review in upcoming plant maintenance window |
| 🟡 MEDIUM | **2** | Planned remediation / configuration audit |
| 🟢 LOW | **0** | Routine architectural enhancement |
| 🔵 INFO | **1** | Documented baseline OT control activity |

### IEC 62443 Foundational Requirements Assessment

The table below maps observed telemetry to all seven IEC 62443-3-3:2018 Foundational Requirements (FRs):

| Foundational Requirement (FR) | Current Technical Posture | Evaluated Target Scope | Gap Summary |
|--------------------------------|---------------------------|------------------------|-------------|
| FR 1: IAC (Identification & Authentication) | ⚠️ MEDIUM Findings | Zone-Dependent (Established per IEC 62443-3-2 Risk Assessment) | ⚠️ 1 observation(s) requiring validation |
| FR 2: UC (Use Control) | ⚠️ INFO Findings | Zone-Dependent (Established per IEC 62443-3-2 Risk Assessment) | ⚠️ 1 observation(s) requiring validation |
| FR 3: SI (System Integrity) | ⚠️ HIGH Findings | Zone-Dependent (Established per IEC 62443-3-2 Risk Assessment) | ⚠️ 3 observation(s) requiring validation |
| FR 4: DC (Data Confidentiality) | ⚠️ HIGH Findings | Zone-Dependent (Established per IEC 62443-3-2 Risk Assessment) | ⚠️ 1 observation(s) requiring validation |
| FR 5: RDF (Restricted Data Flow) | ⚠️ CRITICAL Findings | Zone-Dependent (Established per IEC 62443-3-2 Risk Assessment) | ⚠️ 3 observation(s) requiring validation |
| FR 6: TRE (Timely Response to Events) | ⚠️ HIGH Findings | Zone-Dependent (Established per IEC 62443-3-2 Risk Assessment) | ⚠️ 2 observation(s) requiring validation |
| FR 7: RA (Resource Availability) | Not Assessed in Capture | Zone-Dependent (Established per IEC 62443-3-2 Risk Assessment) | Resource-availability controls not assessed; no selected availability anomaly detected within demonstrated capture. |

> **IEC 62443 Security Level Status**: Preliminary technical observations mapped to selected IEC 62443-3-3 requirements. 
> Per IEC 62443-3-2, target security levels (SL-T) and achieved security levels (SL-A) are established per specific zone 
> and conduit through formal risk assessment and system verification; overall plant-wide SL-A cannot be determined from passive telemetry alone.

### Telemetry & Accounting Basis

Passive packet capture accounted for **504,010 total Ethernet frames** across 15 distinct communication flows:

- **Asset Coverage**: 12 unique assets (10 OT controllers/devices in lab manifest, 2 unclassified endpoints absent from reference inventory).
- **Protocol Metrics**: 9 distinct protocols observed. Counts represent exact non-overlapping frame totals.
- **Process Control Write Activity**: Deep Packet Inspection (DPI) identified **3 distinct write-bearing command function codes** (Modbus FC16 Write Multiple Registers, Modbus FC06 Write Single Register, and HART-IP Command 6 Write Polling Address) across 7 active write communication sessions.
- **Control Separation**: Distinguishes valid process control baselines (e.g., M580 PLC commanding Kiln VFD) from unverified external control commands (e.g., Unregistered Dispatch PC writing to Packaging PLC).

> [!CAUTION]
> **2 CRITICAL finding(s) detected.** These represent cross-zone conduit flows and unauthenticated 
> external access into process controllers. Urgent validation with the plant operations owner is recommended prior 
> to applying firewall rules or port containment.

---

## 2. Asset Inventory (Passive Discovery)

The following assets were identified from passive traffic inspection. Endpoints marked ⚠️ were **not** in the 
lab reference inventory and require physical confirmation before applying isolation rules.

| # | IP Address | MAC Address | Vendor | Device Type / Role | Purdue Level | Protocols Seen | Identity Source | Registry Status |
|---|------------|-------------|--------|--------------------|--------------|----------------|-----------------|-----------------|
| 1 | `10.20.10.11` | `00:80:F4:A1:22:11` | Schneider Electric | Modicon M580 Redundant ePAC (Kiln & Preheater) | Level 1 | Modbus TCP, Modbus UMAS (Schneider FC90), TCP/23 (Potential Telnet) | Supplied by lab manifest | ✅ Registered |
| 2 | `10.20.10.12` | `00:80:F4:A1:22:12` | Schneider Electric | Modicon M580 PLC (Clinker Cooler & TAD) | Level 1 | Modbus TCP | Supplied by lab manifest | ✅ Registered |
| 3 | `10.20.10.21` | `00:80:F4:B2:33:01` | Schneider Electric | Modicon M580 PLC (Crusher & Raw Mill VRM) | Level 1 | Modbus TCP, EtherNet/IP / CIP (Rockwell) | Supplied by lab manifest | ✅ Registered |
| 4 | `10.20.10.31` | `00:80:F4:C3:44:05` | Schneider Electric | Modicon M580 PLC (Cement Mill & Silos) | Level 1 | Modbus TCP, DNP3 | Supplied by lab manifest | ✅ Registered |
| 5 | `10.20.10.41` | `00:80:F4:D4:55:09` | Schneider Electric | Modicon M340 PLC (Packing Plant & Roto-Packer) | Level 1 | Modbus TCP, EtherNet/IP / CIP (Rockwell) | Supplied by lab manifest | ✅ Registered |
| 6 | `10.20.10.101` | `98:F4:AB:12:34:56` | Schneider Electric | Altivar Process ATV930 VFD (Kiln Main Drive) | Level 1 | Modbus TCP | Supplied by lab manifest | ✅ Registered |
| 7 | `10.20.10.150` | `00:0A:DC:33:44:55` | Yokogawa | CENTUM / HART-IP Gas Analyzer Gateway | Level 1 | HART-IP (Yokogawa / Emerson) | Supplied by lab manifest | ✅ Registered |
| 8 | `10.20.20.15` | `00:80:F4:99:11:22` | Schneider Electric | Magelis / Harmony iPC HMI (Central Control Room) | Level 2 | OPC-UA | Supplied by lab manifest | ✅ Registered |
| 9 | `10.20.30.10` | `00:50:56:AA:11:01` | Schneider Electric | EcoStruxure Plant SCADA Primary Server (Citect) | Level 3 | Modbus TCP, OPC-UA, HART-IP (Yokogawa / Emerson), DNP3, SNMP, TCP/445 (Potential SMB) | Supplied by lab manifest | ✅ Registered |
| 10 | `10.20.30.50` | `00:50:56:AA:11:50` | Schneider Electric | Engineering Workstation (EcoStruxure Control Expert) | Level 3 | Modbus UMAS (Schneider FC90) | Supplied by lab manifest | ✅ Registered |
| 11 | `10.20.30.99` | `00:50:56:99:88:77` | Unknown | Cement Dispatch & SAP Billing PC | Unclassified / External IT | Modbus TCP, TCP/445 (Potential SMB) | Inferred — unverified | ⚠️ **NOT IN REGISTRY** |
| 12 | `172.16.5.40` | `00:0C:29:EE:FF:10` | Unknown | Third-Party Burner Vendor Remote Support Laptop | Unclassified / External IT | TCP/23 (Potential Telnet) | Inferred — unverified | ⚠️ **NOT IN REGISTRY** |

### 2.1 Purdue-Level Asset Grouping (Observed vs Reference Manifest)

Below is the automated Purdue structural asset map generated from passive packet traces and reference manifest data.
Devices are color-coded: 🔴 **Red** (Unregistered endpoint / Critical attention), 🟡 **Yellow** (Attention required), 🟢 **Green** (No selected findings observed).

<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 800" style="background:#f8fafc; border-radius:10px; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); width:100%; max-width:960px; height:auto;">
<defs>
  <filter id="shadow" x="-5%" y="-5%" width="110%" height="115%">
    <feDropShadow dx="0" dy="2" stdDeviation="3" flood-opacity="0.08"/>
  </filter>
</defs>

<!-- Header & Legend -->
<rect x="0" y="0" width="960" height="60" fill="#0f172a" rx="10" ry="10" />
<text x="24" y="32" font-size="14.5" font-weight="700" fill="#f8fafc">Purdue-Level Asset Grouping (Observed vs Reference Manifest)</text>
<text x="24" y="48" font-size="10" fill="#94a3b8">Structural inventory grouping derived from passive telemetry and reference manifest (All 12 assets rendered)</text>

<!-- Legend Items -->
<rect x="530" y="24" width="12" height="12" rx="3" fill="#dc2626" />
<text x="548" y="34" font-size="10.5" font-weight="600" fill="#f8fafc">Unregistered / Priority</text>
<rect x="680" y="24" width="12" height="12" rx="3" fill="#f59e0b" />
<text x="698" y="34" font-size="10.5" font-weight="600" fill="#f8fafc">Attention Required</text>
<rect x="810" y="24" width="12" height="12" rx="3" fill="#10b981" />
<text x="828" y="34" font-size="10.5" font-weight="600" fill="#f8fafc">No Findings Observed</text>
<rect x="18" y="80" width="924" height="137" rx="8" fill="#f1f5f9" stroke="#cbd5e1" stroke-width="1.5" />
<text x="32" y="102" font-size="11.5" font-weight="700" fill="#334155" letter-spacing="0.5">LEVEL 3: OPERATIONS &amp; SCADA (2 Assets)</text>
<g filter="url(#shadow)"><rect x="32" y="112" width="210" height="80" rx="6" fill="#FFFBEB" stroke="#F59E0B" stroke-width="2" /><rect x="38" y="118" width="198" height="15" rx="3" fill="#F59E0B" /><text x="137.0" y="129" font-size="8.5" font-weight="700" fill="#ffffff" text-anchor="middle">ATTENTION REQUIRED</text><text x="42" y="149" font-size="11.5" font-weight="700" fill="#0f172a">Schneider Electric</text><text x="42" y="164" font-size="10" fill="#475569">EcoStruxure Plant SCADA ...</text><text x="42" y="181" font-size="10.5" font-weight="600" fill="#2563eb" font-family="monospace">10.20.30.10</text></g>
<g filter="url(#shadow)"><rect x="260" y="112" width="210" height="80" rx="6" fill="#ECFDF5" stroke="#10B981" stroke-width="2" /><rect x="266" y="118" width="198" height="15" rx="3" fill="#10B981" /><text x="365.0" y="129" font-size="8.5" font-weight="700" fill="#ffffff" text-anchor="middle">NO FINDINGS OBSERVED</text><text x="270" y="149" font-size="11.5" font-weight="700" fill="#0f172a">Schneider Electric</text><text x="270" y="164" font-size="10" fill="#475569">Engineering Workstation ...</text><text x="270" y="181" font-size="10.5" font-weight="600" fill="#2563eb" font-family="monospace">10.20.30.50</text></g>
<rect x="18" y="232" width="924" height="137" rx="8" fill="#f1f5f9" stroke="#cbd5e1" stroke-width="1.5" />
<text x="32" y="254" font-size="11.5" font-weight="700" fill="#334155" letter-spacing="0.5">LEVEL 2: AREA SUPERVISION (HMI / EWS) (1 Asset)</text>
<g filter="url(#shadow)"><rect x="32" y="264" width="210" height="80" rx="6" fill="#ECFDF5" stroke="#10B981" stroke-width="2" /><rect x="38" y="270" width="198" height="15" rx="3" fill="#10B981" /><text x="137.0" y="281" font-size="8.5" font-weight="700" fill="#ffffff" text-anchor="middle">NO FINDINGS OBSERVED</text><text x="42" y="301" font-size="11.5" font-weight="700" fill="#0f172a">Schneider Electric</text><text x="42" y="316" font-size="10" fill="#475569">Magelis / Harmony iPC HM...</text><text x="42" y="333" font-size="10.5" font-weight="600" fill="#2563eb" font-family="monospace">10.20.20.15</text></g>
<rect x="18" y="384" width="924" height="229" rx="8" fill="#eff6ff" stroke="#bfdbfe" stroke-width="1.5" />
<text x="32" y="406" font-size="11.5" font-weight="700" fill="#334155" letter-spacing="0.5">LEVEL 1: BASIC CONTROL (PLCS / RTUS / DRIVES) (7 Assets)</text>
<g filter="url(#shadow)"><rect x="32" y="416" width="210" height="80" rx="6" fill="#FEF2F2" stroke="#DC2626" stroke-width="2" /><rect x="38" y="422" width="198" height="15" rx="3" fill="#DC2626" /><text x="137.0" y="433" font-size="8.5" font-weight="700" fill="#ffffff" text-anchor="middle">CRITICAL ATTENTION</text><text x="42" y="453" font-size="11.5" font-weight="700" fill="#0f172a">Schneider Electric</text><text x="42" y="468" font-size="10" fill="#475569">Modicon M580 Redundant e...</text><text x="42" y="485" font-size="10.5" font-weight="600" fill="#2563eb" font-family="monospace">10.20.10.11</text></g>
<g filter="url(#shadow)"><rect x="260" y="416" width="210" height="80" rx="6" fill="#FFFBEB" stroke="#F59E0B" stroke-width="2" /><rect x="266" y="422" width="198" height="15" rx="3" fill="#F59E0B" /><text x="365.0" y="433" font-size="8.5" font-weight="700" fill="#ffffff" text-anchor="middle">CLEARTEXT PROTOCOL</text><text x="270" y="453" font-size="11.5" font-weight="700" fill="#0f172a">Schneider Electric</text><text x="270" y="468" font-size="10" fill="#475569">Modicon M580 PLC (Clinke...</text><text x="270" y="485" font-size="10.5" font-weight="600" fill="#2563eb" font-family="monospace">10.20.10.12</text></g>
<g filter="url(#shadow)"><rect x="488" y="416" width="210" height="80" rx="6" fill="#FFFBEB" stroke="#F59E0B" stroke-width="2" /><rect x="494" y="422" width="198" height="15" rx="3" fill="#F59E0B" /><text x="593.0" y="433" font-size="8.5" font-weight="700" fill="#ffffff" text-anchor="middle">CLEARTEXT PROTOCOL</text><text x="498" y="453" font-size="11.5" font-weight="700" fill="#0f172a">Schneider Electric</text><text x="498" y="468" font-size="10" fill="#475569">Modicon M580 PLC (Crushe...</text><text x="498" y="485" font-size="10.5" font-weight="600" fill="#2563eb" font-family="monospace">10.20.10.21</text></g>
<g filter="url(#shadow)"><rect x="716" y="416" width="210" height="80" rx="6" fill="#FFFBEB" stroke="#F59E0B" stroke-width="2" /><rect x="722" y="422" width="198" height="15" rx="3" fill="#F59E0B" /><text x="821.0" y="433" font-size="8.5" font-weight="700" fill="#ffffff" text-anchor="middle">CLEARTEXT PROTOCOL</text><text x="726" y="453" font-size="11.5" font-weight="700" fill="#0f172a">Schneider Electric</text><text x="726" y="468" font-size="10" fill="#475569">Modicon M580 PLC (Cement...</text><text x="726" y="485" font-size="10.5" font-weight="600" fill="#2563eb" font-family="monospace">10.20.10.31</text></g>
<g filter="url(#shadow)"><rect x="32" y="508" width="210" height="80" rx="6" fill="#FEF2F2" stroke="#DC2626" stroke-width="2" /><rect x="38" y="514" width="198" height="15" rx="3" fill="#DC2626" /><text x="137.0" y="525" font-size="8.5" font-weight="700" fill="#ffffff" text-anchor="middle">CRITICAL ATTENTION</text><text x="42" y="545" font-size="11.5" font-weight="700" fill="#0f172a">Schneider Electric</text><text x="42" y="560" font-size="10" fill="#475569">Modicon M340 PLC (Packin...</text><text x="42" y="577" font-size="10.5" font-weight="600" fill="#2563eb" font-family="monospace">10.20.10.41</text></g>
<g filter="url(#shadow)"><rect x="260" y="508" width="210" height="80" rx="6" fill="#FFFBEB" stroke="#F59E0B" stroke-width="2" /><rect x="266" y="514" width="198" height="15" rx="3" fill="#F59E0B" /><text x="365.0" y="525" font-size="8.5" font-weight="700" fill="#ffffff" text-anchor="middle">CLEARTEXT PROTOCOL</text><text x="270" y="545" font-size="11.5" font-weight="700" fill="#0f172a">Schneider Electric</text><text x="270" y="560" font-size="10" fill="#475569">Altivar Process ATV930 V...</text><text x="270" y="577" font-size="10.5" font-weight="600" fill="#2563eb" font-family="monospace">10.20.10.101</text></g>
<g filter="url(#shadow)"><rect x="488" y="508" width="210" height="80" rx="6" fill="#FFFBEB" stroke="#F59E0B" stroke-width="2" /><rect x="494" y="514" width="198" height="15" rx="3" fill="#F59E0B" /><text x="593.0" y="525" font-size="8.5" font-weight="700" fill="#ffffff" text-anchor="middle">CLEARTEXT PROTOCOL</text><text x="498" y="545" font-size="11.5" font-weight="700" fill="#0f172a">Yokogawa</text><text x="498" y="560" font-size="10" fill="#475569">CENTUM / HART-IP Gas Ana...</text><text x="498" y="577" font-size="10.5" font-weight="600" fill="#2563eb" font-family="monospace">10.20.10.150</text></g>
<rect x="18" y="628" width="924" height="137" rx="8" fill="#fef2f2" stroke="#fecaca" stroke-width="1.5" />
<text x="32" y="650" font-size="11.5" font-weight="700" fill="#334155" letter-spacing="0.5">UNCLASSIFIED / EXTERNAL IT (2 Assets)</text>
<g filter="url(#shadow)"><rect x="32" y="660" width="210" height="80" rx="6" fill="#FEF2F2" stroke="#DC2626" stroke-width="2" /><rect x="38" y="666" width="198" height="15" rx="3" fill="#DC2626" /><text x="137.0" y="677" font-size="8.5" font-weight="700" fill="#ffffff" text-anchor="middle">UNREGISTERED — VALIDATE</text><text x="42" y="697" font-size="11.5" font-weight="700" fill="#0f172a">Unknown</text><text x="42" y="712" font-size="10" fill="#475569">Cement Dispatch &amp; SAP Bi...</text><text x="42" y="729" font-size="10.5" font-weight="600" fill="#2563eb" font-family="monospace">10.20.30.99</text></g>
<g filter="url(#shadow)"><rect x="260" y="660" width="210" height="80" rx="6" fill="#FEF2F2" stroke="#DC2626" stroke-width="2" /><rect x="266" y="666" width="198" height="15" rx="3" fill="#DC2626" /><text x="365.0" y="677" font-size="8.5" font-weight="700" fill="#ffffff" text-anchor="middle">UNREGISTERED — VALIDATE</text><text x="270" y="697" font-size="11.5" font-weight="700" fill="#0f172a">Unknown</text><text x="270" y="712" font-size="10" fill="#475569">Third-Party Burner Vendo...</text><text x="270" y="729" font-size="10.5" font-weight="600" fill="#2563eb" font-family="monospace">172.16.5.40</text></g>
</svg>

### 2.2 Vendor-Specific Hardware Vulnerabilities (CISA / Authoritative Advisory Cross-Reference)

Discovered asset hardware and controllers match the following published OT advisories. 
Because passive analysis cannot inspect internal firmware binaries, unverified versions are reported as candidate advisories:

| Identified Product | Identification Basis | Installed Version | Affected Range | Applicability Status | Source Advisory | Recommended Action | Affected Asset IDs |
|--------------------|----------------------|-------------------|----------------|----------------------|-----------------|--------------------|--------------------|
| Modicon M580, M340, Quantum Controllers & EcoStruxure Control Expert | Supplied by lab manifest | Unknown (Passive capture cannot query internal firmware) | Modicon M580 (all versions), M340 (all versions), EcoStruxure Control Expert (< V15.0 SP1) | Candidate advisory — firmware / version validation required | [CVE-2021-22779 (ICSA-21-194-01)](https://www.cisa.gov/news-events/ics-advisories/icsa-21-194-01) | Validate controller firmware & Control Expert version; configure IP Access Control Lists (ACL) in Control Expert; restrict port 502 to authorized engineering/SCADA stations. | `10.20.10.11` (Modicon M580 Redundant ePAC (Kiln & Preheater))<br>`10.20.10.12` (Modicon M580 PLC (Clinker Cooler & TAD))<br>`10.20.10.21` (Modicon M580 PLC (Crusher & Raw Mill VRM))<br>`10.20.10.31` (Modicon M580 PLC (Cement Mill & Silos))<br>`10.20.10.41` (Modicon M340 PLC (Packing Plant & Roto-Packer))<br>`10.20.30.50` (Engineering Workstation (EcoStruxure Control Expert)) |
| Modicon M340 & Quantum Controllers | Supplied by lab manifest | Unknown (Passive capture cannot query internal firmware) | Modicon M340 (all versions prior to BMXP34 SV3.30), Quantum (all versions) | Candidate advisory — firmware / version validation required | [CVE-2020-7537 (ICSA-20-343-04)](https://www.cisa.gov/news-events/ics-advisories/icsa-20-343-04) | Deploy network conduit ACLs to restrict Modbus port 502 strictly to authorized SCADA polling servers; schedule firmware update during planned turnaround. | `10.20.10.41` (Modicon M340 PLC (Packing Plant & Roto-Packer)) |


---

## 3. OT Protocol Map

| Protocol | Packets | Share | Risk Level | Encryption / Cryptographic Protection | Authentication Mechanism |
|----------|---------|-------|------------|---------------------------------------|--------------------------|
| Modbus TCP | 287,700 | 57.1% | HIGH | ❌ None (Plaintext byte stream) | ❌ None (No station auth) |
| OPC-UA | 82,100 | 16.3% | VARIABLE | ⚠️ Depends on negotiated SecurityPolicy (SignAndEncrypt vs None) | ✅ X.509 Certificates / User tokens |
| Modbus UMAS (Schneider FC90) | 42,000 | 8.3% | HIGH | ❌ None (Proprietary engineering byte stream) | ⚠️ Application-level password |
| SNMP | 31,200 | 6.2% | MEDIUM | ⚠️ Depends on version (SNMPv1/v2c cleartext; SNMPv3 authPriv encrypted) | ⚠️ Community string in v1/v2c |
| HART-IP (Yokogawa / Emerson) | 24,800 | 4.9% | HIGH | ⚠️ FieldComm Group standard supports TLS/DTLS; unencrypted in observed flow | ❌ None in observed flow |
| EtherNet/IP / CIP (Rockwell) | 18,400 | 3.7% | HIGH | ❌ None | ⚠️ CIP Security optional |
| DNP3 | 16,620 | 3.3% | HIGH | ❌ None | ⚠️ DNP3-SA optional |
| TCP/445 (Potential SMB) | 850 | 0.2% | HIGH | ⚠️ SMB encryption optional (v3.0+); unauthenticated/cleartext in v1 | ⚠️ NTLM / Kerberos (Depends on domain) |
| TCP/23 (Potential Telnet) | 340 | 0.1% | CRITICAL | ❌ None (Cleartext interactive CLI) | ❌ Cleartext password in transit |

---

## 4. IEC 62443 Technical Findings

### Finding 01 — 🔴 CRITICAL: Unregistered endpoints communicating with simulated Level 1 controllers

| Field | Detail |
|-------|--------|
| **IEC 62443 Control** | SR 5.1 — Network Segmentation |
| **Severity** | CRITICAL |
| **Evidence Confidence** | High (Observed in packet trace) |
| **Validation Status** | Observed in telemetry — Requires plant engineering confirmation |
| **Target Security Level** | Zone-dependent (Evaluated against IEC 62443-3-3:2018 Technical Requirements) |
| **NIST SP 800-82 Reference** | NIST SP 800-82 Rev. 3 §5.1 (Network Segmentation) & §5.2 (Boundary Protection) |
| **MITRE ATT&CK for ICS** | T0886 — Remote Services |
| **Risk Rationale** | Direct external or corporate access to Level 1 controllers creates potential pathways for unauthorized process alteration or ransomware propagation. |

**Observed Telemetry Evidence:**
> Observed 2 communication session(s) where endpoints absent from the lab reference inventory (10.20.30.99, 172.16.5.40) directly target Level 1 process controllers (10.20.10.11, 10.20.10.41). Scenario context: The lab manifest designates these endpoints as dispatch and vendor-support systems. Not established by traffic alone: Actual device ownership, permitted conduits, intervening firewall controls, or operational necessity.

**Recommended Action:**
> Conduct urgent engineering walkdown and review with plant operations before applying isolation. Validate whether these connections serve legitimate operational workflows. If valid, formally document them in the plant asset registry and establish approved conduit boundary rules. If unauthorized, coordinate containment and port isolation with the operations owner.

**Associated Endpoints:** 10.20.30.99, 172.16.5.40, 10.20.10.11, 10.20.10.41

### Finding 02 — 🔴 CRITICAL: TCP/23 (Potential Telnet) unencrypted session observed targeting process controller

| Field | Detail |
|-------|--------|
| **IEC 62443 Control** | SR 5.2 — Zone Boundary Protection |
| **Severity** | CRITICAL |
| **Evidence Confidence** | Medium (Port-based heuristic; payload unparsed) |
| **Validation Status** | Observed in telemetry — Requires vendor tool confirmation |
| **Target Security Level** | Zone-dependent (Evaluated against IEC 62443-3-3:2018 Technical Requirements) |
| **NIST SP 800-82 Reference** | NIST SP 800-82 Rev. 3 §5.3 (Remote Access) & §6.2.6 (System and Communications Protection) |
| **MITRE ATT&CK for ICS** | T0886 — Remote Services |
| **Risk Rationale** | Unencrypted interactive remote administration allows passive eavesdropping and session hijacking if network perimeter is traversed. |

**Observed Telemetry Evidence:**
> Observed TCP port 23 traffic: 172.16.5.40 → 10.20.10.11 (340 packets). Application parsing is port-based heuristic. Telnet transport protocol transmits data without native encryption; if interactive authentication occurred, credentials could be exposed to passive monitoring. Actual credential exposure was not parsed in the captured sample.

**Recommended Action:**
> Validate operational dependencies urgently with designated plant engineering. Determine if controller firmware supports SSH or secure vendor tools. If remote administration is required, restrict traffic via an authenticated Level 3.5 DMZ jump host with MFA. Disable legacy Telnet services during the next scheduled plant maintenance window.

**Associated Endpoints:** 172.16.5.40, 10.20.10.11

### Finding 03 — 🟠 HIGH: TCP/445 (Potential SMB) file-sharing traffic detected targeting supervisory server

| Field | Detail |
|-------|--------|
| **IEC 62443 Control** | SR 5.2 — Zone Boundary Protection |
| **Severity** | HIGH |
| **Evidence Confidence** | Medium (Port-based heuristic) |
| **Validation Status** | Observed in telemetry — Requires operational verification |
| **Target Security Level** | Zone-dependent (Evaluated against IEC 62443-3-3:2018 Technical Requirements) |
| **NIST SP 800-82 Reference** | NIST SP 800-82 Rev. 3 §5.2 (Boundary Protection) |
| **MITRE ATT&CK for ICS** | T0867 — Lateral Tool Transfer |
| **Risk Rationale** | SMB file-sharing across trust zones is the primary propagation vector for commodity ransomware in industrial environments. |

**Observed Telemetry Evidence:**
> Observed TCP port 445 traffic: 10.20.30.99 → 10.20.30.10 (850 packets). Application parsing is port-based heuristic. Direct workstation-to-SCADA file sharing introduces potential malware propagation vectors.

**Recommended Action:**
> Review business necessity of SMB file sharing. Validate whether backup or historian workflows require port 445. Ensure legacy SMBv1 is disabled. Apply conduit filtering at the boundary firewall, and use secure transfer mechanisms (SFTP/HTTPS) where required.

**Associated Endpoints:** 10.20.30.99, 10.20.30.10

### Finding 04 — 🟠 HIGH: Legacy Modbus communication without native cryptographic protection — compensating controls require review

| Field | Detail |
|-------|--------|
| **IEC 62443 Control** | SR 3.1 — Communication Integrity |
| **Severity** | HIGH |
| **Evidence Confidence** | High (Observed in packet trace) |
| **Validation Status** | Observed in telemetry — Protocol design property |
| **Target Security Level** | Zone-dependent (Evaluated against IEC 62443-3-3:2018 Technical Requirements) |
| **NIST SP 800-82 Reference** | NIST SP 800-82 Rev. 3 §6.2.6 (System and Communications Protection) |
| **MITRE ATT&CK for ICS** | T0831 — Manipulate I&C |
| **Risk Rationale** | Industrial protocols lacking cryptographic authentication permit unauthorized register reads and setpoint overrides if network perimeters are breached. |

**Observed Telemetry Evidence:**
> Observed 287,700 Modbus TCP packets across 7 active communication sessions. Standard Modbus protocol specification (port 502) lacks native message encryption and station authentication. Commands and telemetry are transmitted in cleartext, meaning any host with network connectivity can read or issue registers unless constrained by external network controls.

**Recommended Action:**
> Implement network-level compensating controls: enforce strict VLAN boundaries, implement switch-port IP/MAC ACLs, and deploy industrial firewall inspection to permit only approved Modbus function codes between validated SCADA servers and controllers. Enable controller-level access control tables (e.g. Modicon M580 Security ACLs) in Control Expert.

### Finding 05 — 🟠 HIGH: Insecure OPC-UA Channel Configuration (SecurityPolicy#None observed)

| Field | Detail |
|-------|--------|
| **IEC 62443 Control** | SR 4.1 — Information Confidentiality |
| **Severity** | HIGH |
| **Evidence Confidence** | High (Observed in packet trace) |
| **Validation Status** | Observed in telemetry |
| **Target Security Level** | Zone-dependent (Evaluated against IEC 62443-3-3:2018 Technical Requirements) |
| **NIST SP 800-82 Reference** | NIST SP 800-82 Rev. 3 §6.2.6 (System and Communications Protection) |
| **MITRE ATT&CK for ICS** | T0855 — Unauthorized Command Message |
| **Risk Rationale** | Cleartext OPC-UA allows MITM manipulation of supervisory process telemetry and setpoints. |

**Observed Telemetry Evidence:**
> Observed 1 OPC-UA TCP session(s) where channel handshake negotiated SecurityPolicy#None. The OPC-UA SecureChannel was established without cryptographic message signing or encryption. Process variables, setpoints, and session tokens are exposed in cleartext to passive eavesdropping on this channel.

**Recommended Action:**
> Validate operational dependencies with SCADA/HMI vendor. During a planned engineering window, configure OPC-UA servers and clients to require MessageSecurityMode 'SignAndEncrypt' with SecurityPolicy 'Basic256Sha256' or 'Aes128_Sha256_RsaOaep'. Deploy managed X.509 certificates to replace 'None' endpoints.

### Finding 06 — 🟠 HIGH: HART-IP field communication decoded in cleartext — gateway configuration requires review

| Field | Detail |
|-------|--------|
| **IEC 62443 Control** | SR 3.1 — Communication Integrity |
| **Severity** | HIGH |
| **Evidence Confidence** | High (Observed in packet trace) |
| **Validation Status** | Observed in telemetry — Gateway capabilities unconfirmed |
| **Target Security Level** | Zone-dependent (Evaluated against IEC 62443-3-3:2018 Technical Requirements) |
| **NIST SP 800-82 Reference** | NIST SP 800-82 Rev. 3 §6.2.6 (System and Communications Protection) |
| **MITRE ATT&CK for ICS** | T0836 — Modify Parameter |
| **Risk Rationale** | Unencrypted gateway communication allows potential parameter tampering or spoofed readings if conduit access is unrestricted. |

**Observed Telemetry Evidence:**
> The demonstrated HART-IP exchange was decoded in cleartext across 1 session(s). FieldComm Group HART-IP specifications support secure TLS/DTLS profiles; security capabilities and configuration of the represented gateway require validation. Scenario assumptions regarding process telemetry require on-site verification against instrument tag databases.

**Recommended Action:**
> Validate whether deployed gateway hardware supports HART-IP security profiles (TLS/DTLS). If unencrypted legacy operation is required, enforce network-level conduit isolation via a dedicated VLAN with switch ACL allowlists restricting traffic strictly to authorized supervisory controllers.

### Finding 07 — 🟠 HIGH: 2 unregistered active endpoint(s) detected on control network

| Field | Detail |
|-------|--------|
| **IEC 62443 Control** | SR 6.2 — Continuous Monitoring |
| **Severity** | HIGH |
| **Evidence Confidence** | High (Observed in packet trace) |
| **Validation Status** | Observed in telemetry — Requires physical walkdown |
| **Target Security Level** | Zone-dependent (Evaluated against IEC 62443-3-3:2018 Technical Requirements) |
| **NIST SP 800-82 Reference** | NIST SP 800-82 Rev. 3 §5.1 (Network Segmentation) & §6.2.2 |
| **MITRE ATT&CK for ICS** | T0886 — Remote Services |
| **Risk Rationale** | Unmanaged assets on control segments introduce unpatched operating systems and unauthorized bridging pathways. |

**Observed Telemetry Evidence:**
> The following IP addresses were observed generating active traffic but are absent from the lab reference inventory: 10.20.30.99, 172.16.5.40. Identities are inferred from observed traffic behaviors.

**Recommended Action:**
> Conduct a physical walkdown to confirm device ownership, physical switch port location, and business necessity. Update the asset inventory accordingly. Quarantine any endpoint that cannot be validated by plant operations.

### Finding 08 — 🟠 HIGH: Cleartext industrial protocol in use: DNP3

| Field | Detail |
|-------|--------|
| **IEC 62443 Control** | SR 3.1 — Communication Integrity |
| **Severity** | HIGH |
| **Evidence Confidence** | High (Observed in packet trace) |
| **Validation Status** | Observed in telemetry |
| **Target Security Level** | Zone-dependent (Evaluated against IEC 62443-3-3:2018 Technical Requirements) |
| **NIST SP 800-82 Reference** | NIST SP 800-82 Rev. 3 §6.2.6 (System and Communications Protection) |
| **MITRE ATT&CK for ICS** | T0831 — Manipulate I&C |
| **Risk Rationale** | Cleartext DNP3 allows unauthorized command injection if substation network boundaries are breached. |

**Observed Telemetry Evidence:**
> Observed 16,620 DNP3 packets without cryptographic authentication. DNP3 Secure Authentication (DNP3-SA) was not detected in the captured traffic.

**Recommended Action:**
> Where supported by substation equipment, evaluate enabling DNP3-SA (IEEE 1815-2012). For legacy installations, isolate DNP3 circuits onto dedicated VLAN conduits with restricted routing.

### Finding 09 — 🟡 MEDIUM: No identified log-forwarding traffic observed within capture coverage

| Field | Detail |
|-------|--------|
| **IEC 62443 Control** | SR 6.2 — Continuous Monitoring |
| **Severity** | MEDIUM |
| **Evidence Confidence** | Medium (Absence of traffic in monitored TAP span) |
| **Validation Status** | Observed in telemetry — Scope validation required |
| **Target Security Level** | Zone-dependent (Evaluated against IEC 62443-3-3:2018 Technical Requirements) |
| **NIST SP 800-82 Reference** | NIST SP 800-82 Rev. 3 §6.2.4 (Audit and Accountability) |
| **MITRE ATT&CK for ICS** | N/A — Observational Gap |
| **Risk Rationale** | Without centralized event forwarding, detection of intrusions or post-incident root-cause investigation is severely impeded. |

**Observed Telemetry Evidence:**
> Zero syslog (UDP/TCP 514) or encrypted event forwarding observed from SCADA servers, HMIs, or managed switches in the captured span.

**Recommended Action:**
> Request collector configuration, endpoint logging settings, and retention policies from plant IT/OT engineering before determining a compliance gap. If centralized logging is absent, deploy an OT-compatible log aggregator or SIEM forwarder in the Industrial DMZ (L3.5) with NTP synchronization.

### Finding 10 — 🟡 MEDIUM: Cleartext SNMP polling traffic observed — verify community strings

| Field | Detail |
|-------|--------|
| **IEC 62443 Control** | SR 1.3 — Account Management & Credential Protection |
| **Severity** | MEDIUM |
| **Evidence Confidence** | High (Observed in packet trace) |
| **Validation Status** | Observed in telemetry |
| **Target Security Level** | Zone-dependent (Evaluated against IEC 62443-3-3:2018 Technical Requirements) |
| **NIST SP 800-82 Reference** | NIST SP 800-82 Rev. 3 §6.2.1 (Identification and Authentication) |
| **MITRE ATT&CK for ICS** | T0888 — Remote System Information Discovery |
| **Risk Rationale** | SNMPv1/v2c transmits community strings in cleartext; standard strings allow reconnaissance of switch port states and network topologies. |

**Observed Telemetry Evidence:**
> Observed SNMP (UDP 161) polling traffic across 1 session(s).

**Recommended Action:**
> Verify that default community strings ('public', 'private') are not in use. Migrate network devices to SNMPv3 with authentication and privacy (authPriv). If SNMP is unused, disable the service.

### Finding 11 — 🔵 INFO: Baseline process control write operations observed (Subject to plant verification)

| Field | Detail |
|-------|--------|
| **IEC 62443 Control** | SR 2.1 — Authorization Enforcement |
| **Severity** | INFO |
| **Evidence Confidence** | High (Observed in packet trace) |
| **Validation Status** | Observed in telemetry — Baseline profile |
| **Target Security Level** | Zone-dependent (Evaluated against IEC 62443-3-3:2018 Technical Requirements) |
| **NIST SP 800-82 Reference** | NIST SP 800-82 Rev. 3 §6.2.2 (Access Control) |
| **MITRE ATT&CK for ICS** | T0831 — Manipulate I&C |
| **Risk Rationale** | Expected operational control traffic; document as baseline profile. |

**Observed Telemetry Evidence:**
> Detected 3 distinct write-bearing command function codes between authorized engineering/SCADA stations and controllers (e.g. SCADA polling writes, PLC-to-VFD speed reference updates). Observed activity matches normal plant supervisory control patterns.

**Recommended Action:**
> Confirm during site verification that all observed write function codes correspond to approved SCADA tag databases and operational setpoint ranges.

---

## 5. Remediation Roadmap

> **Costing & Implementation Note**: All priority actions assume no additional software licence or hardware costs 
> unless hardware acquisition is explicitly noted. Site engineering, regression testing, operational walkdowns, 
> and change validation efforts are excluded and must be planned within plant turnaround schedules.

Prioritised by operational risk and implementation constraints:

| Priority | Action | Operational Effort | Estimated Capital Cost | Target Timeline |
|----------|--------|--------------------|------------------------|-----------------|
| 🔴 P1 | Conduct urgent engineering walkdown to validate unidentified endpoints (`10.20.30.99`, `172.16.5.40`). If unauthorized, agree containment and port isolation with plant owner | 1-2 days validation | ₹0 (Operational walkdown) | Urgent validation & plant-approved change window |
| 🔴 P1 | Inspect TCP/23 (Telnet) usage on M580 controller; verify vendor engineering tool requirements and restrict external Telnet traffic at switch ACL | Low (1-2 days) | ₹0 (ACL configuration) | Next maintenance window |
| 🔴 P1 | Review TCP/445 (SMB) dependency between IT and SCADA hosts; apply conduit filtering at boundary firewall | Low (1 day) | ₹0 (Firewall rule) | Next maintenance window |
| 🟠 P2 | Implement OT zone segmentation (L1/L2/L3 VLANs and IDMZ between L4 IT and L3 Operations per NIST SP 800-82 Rev. 3 §5.1 & §5.2) | High (2-4 weeks) | ₹2–6L (Industrial switch/firewall configuration) | 30–60 days |
| 🟠 P2 | Deploy Modbus deep-packet-inspection firewall / gateway allowlist to permit only expected master-to-slave commands | Medium (1-2 weeks) | ₹1–3L (Hardware appliance / DPI module) | 30 days |
| 🟠 P2 | Enforce OPC-UA MessageSecurityMode SignAndEncrypt (Disable SecurityPolicy#None for production tags) | Medium (3 days) | ₹0 (Software configuration) | 14 days |
| 🟠 P2 | Restrict HART-IP field gateway communication via dedicated conduit ACL allowlist to authorized supervisory controllers | Medium (1 week) | ₹0 (Switch ACL configuration) | 14 days |
| 🟡 P3 | Upgrade SNMP community strings to SNMPv3 authPriv across all managed network switches and gateways | Medium (3 days) | ₹0 (Switch configuration) | 30 days |
| 🟡 P3 | Deploy central OT Syslog aggregator in Industrial DMZ (L3.5) with NTP synchronisation | Medium (1 week) | ₹50K–2L (Collector server / SIEM connector) | 60 days |

---

## 6. Appendix — Observed OT Communication Sessions (15 Sessions Analyzed)

Complete list of communication flows observed during passive capture (reconciles with total packet count):

| # | Source | Destination | Protocol | Packets | Write Operation? | Control Context |
|---|--------|-------------|----------|---------|------------------|-----------------|
| 1 | `10.20.30.10:50120` | `10.20.10.11:502` | Modbus TCP | 110,000 | ⚠️ YES (Write) | SCADA Server Polling / Setpoint Write (M580 Kiln) |
| 2 | `10.20.30.10:50121` | `10.20.10.12:502` | Modbus TCP | 45,000 | No (Read-Only) | SCADA Server Polling (M580 Clinker Cooler) |
| 3 | `10.20.30.10:50122` | `10.20.10.21:502` | Modbus TCP | 55,000 | ⚠️ YES (Write) | SCADA Server Polling / Setpoint Write (M580 Raw Mill) |
| 4 | `10.20.30.10:50123` | `10.20.10.31:502` | Modbus TCP | 35,000 | No (Read-Only) | SCADA Server Polling (M580 Cement Mill) |
| 5 | `10.20.30.10:50124` | `10.20.10.41:502` | Modbus TCP | 20,000 | No (Read-Only) | SCADA Server Polling (M340 Packing Plant) |
| 6 | `10.20.10.11:49100` | `10.20.10.101:502` | Modbus TCP | 18,200 | ⚠️ YES (Write) | Expected Process Baseline: Kiln PLC → Kiln VFD speed control |
| 7 | `10.20.30.99:59100` | `10.20.10.41:502` | Modbus TCP | 4,500 | ⚠️ YES (Write) | ⚠️ Unregistered Dispatch PC → Packing PLC (Requires investigation) |
| 8 | `10.20.30.50:49800` | `10.20.10.11:502` | Modbus UMAS (Schneider FC90) | 42,000 | ⚠️ YES (Write) | Engineering Workstation (Control Expert) Program Upload / Diagnostic |
| 9 | `10.20.20.15:54840` | `10.20.30.10:4840` | OPC-UA | 82,100 | No (Read-Only) | Central Control Room HMI ↔ SCADA Server Telemetry Feed |
| 10 | `10.20.30.10:55094` | `10.20.10.150:5094` | HART-IP (Yokogawa / Emerson) | 24,800 | ⚠️ YES (Write) | SCADA Server Polling Gas Analyzer Gateway |
| 11 | `10.20.10.41:44818` | `10.20.10.21:44818` | EtherNet/IP / CIP (Rockwell) | 18,400 | No (Read-Only) | Packing Plant PLC ↔ Raw Mill Interlock Signaling |
| 12 | `10.20.30.10:49200` | `10.20.10.31:20000` | DNP3 | 16,620 | No (Read-Only) | Substation Power Monitor Telemetry Polling |
| 13 | `10.20.30.10:50161` | `10.20.10.11:161` | SNMP | 31,200 | No (Read-Only) | Network Health & Switch Port MIB-II Polling |
| 14 | `172.16.5.40:51234` | `10.20.10.11:23` | TCP/23 (Potential Telnet) | 340 | Not determined | ⚠️ External Vendor Subnet → Kiln PLC (Cleartext Remote Access Heuristic) |
| 15 | `10.20.30.99:49445` | `10.20.30.10:445` | TCP/445 (Potential SMB) | 850 | Not determined | ⚠️ Unregistered Dispatch PC → SCADA Server (File Sharing Heuristic) |

*Total Reconciled Frames in Appendix: 504,010*

---

*Demonstration report generated by **IndusProbe v1.1-demonstrator** — Industrial OT Passive Scanner & IEC 62443 Analyser*
*Notice: Synthetic dataset for technology demonstration purposes only.*