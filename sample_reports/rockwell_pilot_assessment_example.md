# Industrial OT Network Passive Visibility & Telemetry Assessment

> ℹ️ **PASSIVE LISTEN-ONLY ASSESSMENT — ZERO ACTIVE TRANSMISSION**  
> This assessment was conducted exclusively via passive network monitoring and packet analysis.  
> Zero packets were transmitted or injected into any operational control system or field network.  
> **Pilot Scope**: Validated baseline strictly bounded to Schneider Electric (Modbus TCP / UMAS subset) and Rockwell Automation (EtherNet/IP / CIP subset).

| Metadata Field | Value |
|----------------|-------|
| **Facility / Context** | Rockwell Automation Pilot Installation |
| **Target Unit / Segment** | Packaging Facility — Line 1 ControlLogix |
| **Assessment Date** | 2026-11-11 |
| **Capture Telemetry** | Passive Mirror Session (68 frames) |
| **Total Packets Analysed** | 68 Ethernet frames |
| **Assessment Engine** | IndusProbe v1.1 Passive Engine |
| **Reviewer Status** | Pending Analyst Engineering Review |
| **Document Version** | v1.1-pilot-rockwell |
| **Classification** | CONFIDENTIAL — Operational Technology Assessment |
| **Pilot Scope Target** | Schneider Electric & Rockwell Automation Baseline |

---

> **Analytical Methodology**: Purely passive listen-only capture. All technical observations are derived 
> from physical packet headers, protocol state, and application payload decoding without intrusive probing.

---

## 1. Executive Summary

### Risk Summary

| Severity | Count | Initial Operational Treatment |
|----------|-------|-------------------------------|
| 🔴 CRITICAL | **2** | Urgent validation & containment with plant engineering |
| 🟠 HIGH | **1** | Review in upcoming plant maintenance window |
| 🟡 MEDIUM | **1** | Planned remediation / configuration audit |
| 🟢 LOW | **0** | Routine architectural enhancement |
| 🔵 INFO | **0** | Documented baseline OT control activity |

### IEC 62443 Foundational Requirements Assessment

The table below maps observed telemetry to all seven IEC 62443-3-3:2018 Foundational Requirements (FRs):

| Foundational Requirement (FR) | Current Technical Posture | Evaluated Target Scope | Gap Summary |
|--------------------------------|---------------------------|------------------------|-------------|
| FR 1: IAC (Identification & Authentication) | ✅ Baseline Normal | Zone-Dependent (Established per IEC 62443-3-2 Risk Assessment) | ✅ No violations observed in passive trace |
| FR 2: UC (Use Control) | ⚠️ CRITICAL Findings | Zone-Dependent (Established per IEC 62443-3-2 Risk Assessment) | ⚠️ 1 observation(s) requiring validation |
| FR 3: SI (System Integrity) | ✅ Baseline Normal | Zone-Dependent (Established per IEC 62443-3-2 Risk Assessment) | ✅ No violations observed in passive trace |
| FR 4: DC (Data Confidentiality) | ✅ Baseline Normal | Zone-Dependent (Established per IEC 62443-3-2 Risk Assessment) | ✅ No violations observed in passive trace |
| FR 5: RDF (Restricted Data Flow) | ⚠️ CRITICAL Findings | Zone-Dependent (Established per IEC 62443-3-2 Risk Assessment) | ⚠️ 1 observation(s) requiring validation |
| FR 6: TRE (Timely Response to Events) | ⚠️ HIGH Findings | Zone-Dependent (Established per IEC 62443-3-2 Risk Assessment) | ⚠️ 2 observation(s) requiring validation |
| FR 7: RA (Resource Availability) | Not Assessed in Capture | Zone-Dependent (Established per IEC 62443-3-2 Risk Assessment) | Resource-availability controls not assessed; no selected availability anomaly detected within demonstrated capture. |

> **IEC 62443 Security Level Status**: Preliminary technical observations mapped to selected IEC 62443-3-3 requirements. 
> Per IEC 62443-3-2, target security levels (SL-T) and achieved security levels (SL-A) are established per specific zone 
> and conduit through formal risk assessment and system verification; overall plant-wide SL-A cannot be determined from passive telemetry alone.

### Telemetry & Accounting Basis

Passive packet capture accounted for **68 total Ethernet frames** across 3 distinct communication flows:

- **Asset Coverage**: 3 unique assets (2 OT controllers/devices identified, 1 unclassified endpoints).
- **Protocol Metrics**: 1 distinct protocols observed.
- **Process Control Write Activity**: Deep Packet Inspection (DPI) identified **2 active write-bearing communication session(s)**.
- **Control Separation**: Distinguishes valid process control baselines from unverified or external control commands.

> [!CAUTION]
> **2 CRITICAL finding(s) detected.** These represent cross-zone conduit flows and unauthenticated 
> external access into process controllers. Urgent validation with the plant operations owner is recommended prior 
> to applying firewall rules or port containment.

---

## 2. Asset Inventory (Passive Discovery)

The following assets were identified from passive traffic inspection. Endpoints marked ⚠️ were **not** in the 
reference inventory and require physical confirmation before applying isolation rules.

| # | IP Address | MAC Address | Observed Vendor | Model / Product Code | Identification Evidence | Confidence | Purdue Level | Protocols Seen | Registry Status |
|---|------------|-------------|-----------------|----------------------|-------------------------|------------|--------------|----------------|-----------------|
| 1 | `192.168.20.21` | `00:00:bc:88:99:aa` | Rockwell Automation | 1756-L83E ControlLogix | CIP_IDENTITY | HIGH | Level 1 | EtherNet/IP / CIP (Rockwell) | ⚠️ **NOT IN REGISTRY** |
| 2 | `192.168.20.22` | `00:08:28:33:44:55` | Rockwell Automation | ControlLogix | OUI_INFERENCE | MEDIUM | Level 1 | EtherNet/IP / CIP (Rockwell) | ⚠️ **NOT IN REGISTRY** |
| 3 | `192.168.20.100` | `00:50:56:fe:dc:ba` | Rockwell Automation | 1756-L83E ControlLogix | CIP_IDENTITY | HIGH | Unknown | EtherNet/IP / CIP (Rockwell) | ⚠️ **NOT IN REGISTRY** |

### 2.1 Purdue-Level Asset Grouping

Below is the automated Purdue structural asset map generated from passive packet traces and reference inventory data.
Devices are color-coded: 🔴 **Red** (Unregistered endpoint / Critical attention), 🟡 **Yellow** (Attention required), 🟢 **Green** (No selected findings observed).

<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 404" style="background:#f8fafc; border-radius:10px; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); width:100%; max-width:960px; height:auto;">
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
<rect x="18" y="80" width="924" height="137" rx="8" fill="#eff6ff" stroke="#bfdbfe" stroke-width="1.5" />
<text x="32" y="102" font-size="11.5" font-weight="700" fill="#334155" letter-spacing="0.5">LEVEL 1: BASIC CONTROL (PLCS / RTUS / DRIVES) (2 Assets)</text>
<g filter="url(#shadow)"><rect x="32" y="112" width="210" height="80" rx="6" fill="#FEF2F2" stroke="#DC2626" stroke-width="2" /><rect x="38" y="118" width="198" height="15" rx="3" fill="#DC2626" /><text x="137.0" y="129" font-size="8.5" font-weight="700" fill="#ffffff" text-anchor="middle">UNREGISTERED — VALIDATE</text><text x="42" y="149" font-size="11.5" font-weight="700" fill="#0f172a">Rockwell Automatio</text><text x="42" y="164" font-size="10" fill="#475569">ControlLogix / CompactLo...</text><text x="42" y="181" font-size="10.5" font-weight="600" fill="#2563eb" font-family="monospace">192.168.20.21</text></g>
<g filter="url(#shadow)"><rect x="260" y="112" width="210" height="80" rx="6" fill="#FEF2F2" stroke="#DC2626" stroke-width="2" /><rect x="266" y="118" width="198" height="15" rx="3" fill="#DC2626" /><text x="365.0" y="129" font-size="8.5" font-weight="700" fill="#ffffff" text-anchor="middle">UNREGISTERED — VALIDATE</text><text x="270" y="149" font-size="11.5" font-weight="700" fill="#0f172a">Rockwell Automatio</text><text x="270" y="164" font-size="10" fill="#475569">ControlLogix</text><text x="270" y="181" font-size="10.5" font-weight="600" fill="#2563eb" font-family="monospace">192.168.20.22</text></g>
<rect x="18" y="232" width="924" height="137" rx="8" fill="#fef2f2" stroke="#fecaca" stroke-width="1.5" />
<text x="32" y="254" font-size="11.5" font-weight="700" fill="#334155" letter-spacing="0.5">UNCLASSIFIED / EXTERNAL IT (1 Asset)</text>
<g filter="url(#shadow)"><rect x="32" y="264" width="210" height="80" rx="6" fill="#FEF2F2" stroke="#DC2626" stroke-width="2" /><rect x="38" y="270" width="198" height="15" rx="3" fill="#DC2626" /><text x="137.0" y="281" font-size="8.5" font-weight="700" fill="#ffffff" text-anchor="middle">UNREGISTERED — VALIDATE</text><text x="42" y="301" font-size="11.5" font-weight="700" fill="#0f172a">Rockwell Automatio</text><text x="42" y="316" font-size="10" fill="#475569">Unknown Device</text><text x="42" y="333" font-size="10.5" font-weight="600" fill="#2563eb" font-family="monospace">192.168.20.100</text></g>
</svg>

### 2.2 Known Vulnerability & Advisory Correlation Status

> ℹ️ **AUTOMATED ADVISORY EVALUATION NOT ENABLED**  
> Automated vulnerability correlation and CSAF advisory evaluation are disabled for this passive assessment.  
> Conclusively matching CVEs to operational OT controllers requires verified firmware versions, hardware revisions, 
> and manual engineering walkdowns. Unverified version assumptions are omitted to prevent misinformed operational decisions.


---

## 3. OT Protocol Map

> ℹ️ **SCOPED PILOT TARGET — PROTOCOL CLASSIFICATION**  
> Validated parsing and operation classification are strictly bounded to Schneider Electric (Modbus TCP / UMAS subset) 
> and Rockwell Automation (EtherNet/IP / CIP subset).  
> Additional protocol traffic (Siemens S7, DNP3, HART-IP, OPC-UA, etc.) is catalogued as observed network telemetry only.

| Protocol | Packets | Share | Risk Level | Encryption / Cryptographic Protection | Authentication Mechanism |
|----------|---------|-------|------------|---------------------------------------|--------------------------|
| EtherNet/IP / CIP (Rockwell) | 68 | 100.0% | HIGH | ❌ None | ⚠️ CIP Security optional |

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
> Observed 2 communication session(s) where endpoints absent from the reference inventory (192.168.20.100) directly target Level 1 process controllers (192.168.20.21, 192.168.20.22). Not established by traffic alone: Actual device ownership, permitted conduits, intervening firewall controls, or operational necessity.

**Recommended Action:**
> Conduct urgent engineering walkdown and review with plant operations before applying isolation. Validate whether these connections serve legitimate operational workflows. If valid, formally document them in the plant asset registry and establish approved conduit boundary rules. If unauthorized, coordinate containment and port isolation with the operations owner.

**Associated Endpoints:** 192.168.20.100, 192.168.20.21, 192.168.20.22

### Finding 02 — 🔴 CRITICAL: Control write commands originating from uninventoried endpoints

| Field | Detail |
|-------|--------|
| **IEC 62443 Control** | SR 2.1 — Authorization Enforcement |
| **Severity** | CRITICAL |
| **Evidence Confidence** | High (Observed in packet trace) |
| **Validation Status** | Observed in telemetry — Requires engineering confirmation |
| **Target Security Level** | Zone-dependent (Evaluated against IEC 62443-3-3:2018 Technical Requirements) |
| **NIST SP 800-82 Reference** | NIST SP 800-82 Rev. 3 §6.2.2 (Access Control) & §6.2.6 |
| **MITRE ATT&CK for ICS** | T0831 — Manipulate I&C |
| **Risk Rationale** | Write commands from unverified systems can alter equipment setpoints, override safety trips, or cause equipment damage. |

**Observed Telemetry Evidence:**
> Detected 10 write-type command message(s) originating from host(s) absent from the reference inventory: 192.168.20.100. These endpoints issued direct Modbus register write commands to process controllers.

**Recommended Action:**
> Urgently trace and validate the physical switch port connected to these endpoints with plant engineering. Verify why non-registered machines have routing access to process controllers and block unauthorized command sources.

### Finding 03 — 🟠 HIGH: 3 unregistered active endpoint(s) detected on control network

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
> The following IP addresses were observed generating active traffic but are absent from the reference inventory: 192.168.20.100, 192.168.20.21, 192.168.20.22. Identities are inferred from observed traffic behaviors.

**Recommended Action:**
> Conduct a physical walkdown to confirm device ownership, physical switch port location, and business necessity. Update the asset inventory accordingly. Quarantine any endpoint that cannot be validated by plant operations.

### Finding 04 — 🟡 MEDIUM: No identified log-forwarding traffic observed within capture coverage

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

---

## 5. Remediation Roadmap

> **Costing & Implementation Note**: All priority actions assume no additional software licence or hardware costs 
> unless hardware acquisition is explicitly noted. Site engineering, regression testing, operational walkdowns, 
> and change validation efforts are excluded and must be planned within plant turnaround schedules.

Prioritised by operational risk and implementation constraints:

| Priority | Action | Operational Effort | Estimated Capital Cost | Target Timeline |
|----------|--------|--------------------|------------------------|-----------------|
| 🔴 P1 | Conduct urgent engineering walkdown to validate unidentified endpoints (`10.20.30.99`, `172.16.5.40`). If unauthorized, agree containment and port isolation with plant owner | 1-2 days validation | ₹0 (Operational walkdown) | Urgent validation & plant-approved change window |
| 🟠 P2 | Implement OT zone segmentation (L1/L2/L3 VLANs and IDMZ between L4 IT and L3 Operations per NIST SP 800-82 Rev. 3 §5.1 & §5.2) | High (2-4 weeks) | ₹2–6L (Industrial switch/firewall configuration) | 30–60 days |
| 🟠 P2 | Deploy Modbus deep-packet-inspection firewall / gateway allowlist to permit only expected master-to-slave commands | Medium (1-2 weeks) | ₹1–3L (Hardware appliance / DPI module) | 30 days |
| 🟡 P3 | Deploy central OT Syslog aggregator in Industrial DMZ (L3.5) with NTP synchronisation | Medium (1 week) | ₹50K–2L (Collector server / SIEM connector) | 60 days |

---

## 6. Appendix — Observed OT Communication Sessions (3 Sessions Analyzed)

Complete list of communication flows observed during passive capture (reconciles with total packet count):

| # | Source Endpoint | Destination Endpoint | Protocol & Port | Total Packets | Read PDUs | Write PDUs | Undecoded / Unsupported | Session Classification |
|---|-----------------|----------------------|-----------------|---------------|-----------|------------|-------------------------|------------------------|
| 1 | `192.168.20.100:49300` | `192.168.20.21:44818` | EtherNet/IP / CIP (Rockwell) | 50 | 41 | 8 | 1 | `WRITE_OR_CONTROL` |
| 2 | `192.168.20.21:44818` | `192.168.20.100:49300` | EtherNet/IP / CIP (Rockwell) | 1 | 1 | 0 | 0 | `READ_ONLY` |
| 3 | `192.168.20.100:49301` | `192.168.20.22:44818` | EtherNet/IP / CIP (Rockwell) | 17 | 15 | 2 | 0 | `WRITE_OR_CONTROL` |

*Total Reconciled Frames in Appendix: 68*

---

*Assessment report generated by **IndusProbe v1.1** — Industrial OT Passive Visibility & Assessment Engine*  
*Notice: Listen-only passive inspection. Bounded to Schneider Electric and Rockwell Automation pilot baseline.*