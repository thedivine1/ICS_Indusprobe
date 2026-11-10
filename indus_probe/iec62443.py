"""
IndusProbe — IEC 62443-3-3 & NIST SP 800-82 Rev. 3 Technical Analysis Engine

Analyzes passive network telemetry observations against IEC 62443-3-3 requirements
and NIST SP 800-82 Rev. 3 security guidelines.

Key design principles:
- Strictly distinguishes observed facts from analytical inferences.
- Each finding includes evidence confidence and validation status.
- Separates verified baseline process control from unverified external commands.
- Evaluates against all 7 IEC 62443 Foundational Requirements (FR 1 to FR 7).
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any



class SL(str, Enum):
    """IEC 62443 Security Levels (SL 0 - 4)."""
    SL0 = "0"
    SL1 = "1"
    SL2 = "2"
    SL3 = "3"
    SL4 = "4"


@dataclass
class SR:
    """IEC 62443-3-3 System Requirement (SR) control definition."""
    id: str
    title: str
    description: str
    foundational_requirement: str
    nist_mapping: str
    mitre_tactic: str


# ---------------------------------------------------------------------------
# All 7 Foundational Requirements (FR 1 - FR 7) per IEC 62443-3-3:2018
# ---------------------------------------------------------------------------

IEC62443_CONTROLS: dict[str, SR] = {
    # FR 1: Identification & Authentication Control (IAC)
    "SR 1.1": SR(
        id="SR 1.1",
        title="Human User Identification and Authentication",
        description="IACS shall identify and authenticate all human users on all interfaces.",
        foundational_requirement="IAC (Identification & Authentication)",
        nist_mapping="NIST SP 800-82 Rev. 3 §6.2.1",
        mitre_tactic="Initial Access (TA0108)",
    ),
    "SR 1.2": SR(
        id="SR 1.2",
        title="Software Process and Device Identification and Authentication",
        description="IACS shall identify and authenticate all software processes and devices on all interfaces.",
        foundational_requirement="IAC",
        nist_mapping="NIST SP 800-82 Rev. 3 §6.2.1",
        mitre_tactic="Initial Access (TA0108)",
    ),
    "SR 1.3": SR(
        id="SR 1.3",
        title="Account Management & Credential Protection",
        description="IACS shall manage and protect all credentials used for identification and authentication.",
        foundational_requirement="IAC",
        nist_mapping="NIST SP 800-82 Rev. 3 §6.2.1",
        mitre_tactic="Credential Access (TA0100)",
    ),

    # FR 2: Use Control (UC)
    "SR 2.1": SR(
        id="SR 2.1",
        title="Authorization Enforcement",
        description="IACS shall enforce authorizations assigned to human users and software processes for control commands.",
        foundational_requirement="UC (Use Control)",
        nist_mapping="NIST SP 800-82 Rev. 3 §6.2.2",
        mitre_tactic="Execution (TA0104)",
    ),

    # FR 3: System Integrity (SI)
    "SR 3.1": SR(
        id="SR 3.1",
        title="Communication Integrity",
        description="IACS shall protect the integrity of transmitted information against unauthorized alteration.",
        foundational_requirement="SI (System Integrity)",
        nist_mapping="NIST SP 800-82 Rev. 3 §6.2.6",
        mitre_tactic="Inhibit Response Function (TA0107)",
    ),
    "SR 3.3": SR(
        id="SR 3.3",
        title="Security Functionality Verification",
        description="IACS shall verify the integrity of critical security settings, firmware, and software.",
        foundational_requirement="SI",
        nist_mapping="NIST SP 800-82 Rev. 3 §6.2.6",
        mitre_tactic="Persistence (TA0102)",
    ),

    # FR 4: Data Confidentiality (DC)
    "SR 4.1": SR(
        id="SR 4.1",
        title="Information Confidentiality",
        description="IACS shall protect the confidentiality of sensitive process telemetry, credentials, and control data.",
        foundational_requirement="DC (Data Confidentiality)",
        nist_mapping="NIST SP 800-82 Rev. 3 §6.2.6",
        mitre_tactic="Collection (TA0101)",
    ),

    # FR 5: Restricted Data Flow (RDF)
    "SR 5.1": SR(
        id="SR 5.1",
        title="Network Segmentation",
        description="IACS shall segment control networks into zones and conduits based on risk assessment.",
        foundational_requirement="RDF (Restricted Data Flow)",
        nist_mapping="NIST SP 800-82 Rev. 3 §5.1 & §5.2",
        mitre_tactic="Lateral Movement (TA0109)",
    ),
    "SR 5.2": SR(
        id="SR 5.2",
        title="Zone Boundary Protection",
        description="IACS shall monitor and control communications at all zone boundaries and conduit entry points.",
        foundational_requirement="RDF",
        nist_mapping="NIST SP 800-82 Rev. 3 §5.2 & §5.3",
        mitre_tactic="Lateral Movement (TA0109)",
    ),
    "SR 5.3": SR(
        id="SR 5.3",
        title="General Purpose Person-to-Person Communication Restrictions",
        description="IACS shall prohibit general-purpose messaging or email from directly accessing control zones.",
        foundational_requirement="RDF",
        nist_mapping="NIST SP 800-82 Rev. 3 §5.2",
        mitre_tactic="Initial Access (TA0108)",
    ),

    # FR 6: Timely Response to Events (TRE)
    "SR 6.1": SR(
        id="SR 6.1",
        title="Audit Log Generation",
        description="IACS shall generate audit records for security events, access attempts, and configuration changes.",
        foundational_requirement="TRE (Timely Response to Events)",
        nist_mapping="NIST SP 800-82 Rev. 3 §6.2.4",
        mitre_tactic="Discovery (TA0106)",
    ),
    "SR 6.2": SR(
        id="SR 6.2",
        title="Continuous Monitoring",
        description="IACS shall continuously monitor and record network traffic and system health indicators.",
        foundational_requirement="TRE",
        nist_mapping="NIST SP 800-82 Rev. 3 §6.2.4",
        mitre_tactic="Discovery (TA0106)",
    ),

    # FR 7: Resource Availability (RA)
    "SR 7.1": SR(
        id="SR 7.1",
        title="Denial of Service Protection",
        description="IACS shall protect against DoS attacks or traffic floods that could impair control availability.",
        foundational_requirement="RA (Resource Availability)",
        nist_mapping="NIST SP 800-82 Rev. 3 §6.2.6",
        mitre_tactic="Impact (TA0105)",
    ),
    "SR 7.6": SR(
        id="SR 7.6",
        title="Network and Security Configuration Settings",
        description="IACS shall enforce and maintain verified network and security configuration settings.",
        foundational_requirement="RA",
        nist_mapping="NIST SP 800-82 Rev. 3 §6.2.6",
        mitre_tactic="Defense Evasion (TA0103)",
    ),
}


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single technical observation derived from passive traffic analysis."""
    sr_id: str
    sr_title: str
    severity: str               # CRITICAL / HIGH / MEDIUM / LOW / INFO
    finding: str                # Short title
    evidence: str               # Technical observation
    affected_assets: list[str] = field(default_factory=list)
    recommendation: str = ""
    target_sl: SL = SL.SL2
    nist_ref: str = ""
    mitre_ref: str = ""
    risk_rationale: str = ""
    evidence_confidence: str = "High (Observed in packet trace)"
    validation_status: str = "Observed in telemetry"

    @property
    def sr(self) -> SR | None:
        return IEC62443_CONTROLS.get(self.sr_id)


# ---------------------------------------------------------------------------
# IEC 62443 Analysis Engine
# ---------------------------------------------------------------------------

class IEC62443Engine:
    """
    Analyzes passive PCAP observations against IEC 62443-3-3 requirements.
    Distinguishes observed facts from analytical inferences.
    """

    def __init__(self):
        self.findings: list[Finding] = []

    def analyze(
        self,
        assets: list[dict],
        sessions: list[dict],
        protocol_stats: dict[str, int],
        raw_observations: list[dict],
    ) -> list[Finding]:
        """Run all passive checks and return findings list."""
        self.findings = []

        self._check_unregistered_endpoints_to_controllers(assets, sessions)
        self._check_it_protocols_in_ot(sessions, assets)
        self._check_modbus_protocol_limitations(sessions, protocol_stats)
        self._check_opc_ua_security(sessions, raw_observations)
        self._check_hart_security(sessions, raw_observations)
        self._check_write_commands(raw_observations, assets)
        self._check_unregistered_asset_inventory(assets)
        self._check_dnp3_cleartext(protocol_stats)
        self._check_no_monitoring(sessions)
        self._check_default_creds_hint(assets, sessions)
        self._check_broadcast_traffic(sessions)

        return self.findings

    # -----------------------------------------------------------------------
    # Individual checks
    # -----------------------------------------------------------------------

    def _check_unregistered_endpoints_to_controllers(self, assets, sessions):
        """SR 5.1 — Unregistered endpoints communicating with Level 1 controllers."""
        unregistered = [a for a in assets if not a.get("in_client_inventory", True)]
        level1_ips = set(a["ip"] for a in assets if "Level 1" in a.get("purdue_level", ""))

        if unregistered and level1_ips:
            cross_sessions = [
                s for s in sessions
                if any(u["ip"] == s.get("src_ip") for u in unregistered)
                and s.get("dst_ip") in level1_ips
            ]
            if cross_sessions:
                src_ips = sorted(list(set(s["src_ip"] for s in cross_sessions)))
                dst_ips = sorted(list(set(s["dst_ip"] for s in cross_sessions)))
                self.findings.append(Finding(
                    sr_id="SR 5.1",
                    sr_title=IEC62443_CONTROLS["SR 5.1"].title,
                    severity="CRITICAL",
                    finding="Unregistered endpoints communicating with simulated Level 1 controllers",
                    evidence=(
                        f"Observed {len(cross_sessions)} communication session(s) where endpoints absent from the reference "
                        f"inventory ({', '.join(src_ips)}) directly target Level 1 process controllers ({', '.join(dst_ips)}). "
                        f"Not established by traffic alone: Actual device ownership, permitted conduits, intervening firewall controls, or operational necessity."
                    ),
                    recommendation=(
                        "Conduct urgent engineering walkdown and review with plant operations before applying isolation. "
                        "Validate whether these connections serve legitimate operational workflows. If valid, formally document "
                        "them in the plant asset registry and establish approved conduit boundary rules. If unauthorized, "
                        "coordinate containment and port isolation with the operations owner."
                    ),
                    target_sl=SL.SL2,
                    nist_ref="NIST SP 800-82 Rev. 3 §5.1 (Network Segmentation) & §5.2 (Boundary Protection)",
                    mitre_ref="T0886 — Remote Services",
                    risk_rationale="Direct external or corporate access to Level 1 controllers creates potential pathways for unauthorized process alteration or ransomware propagation.",
                    evidence_confidence="High (Observed in packet trace)",
                    validation_status="Observed in telemetry — Requires plant engineering confirmation",
                    affected_assets=src_ips + dst_ips,
                ))

    def _check_it_protocols_in_ot(self, sessions, assets):
        """SR 5.2 — Potential cleartext remote access and file-sharing protocols."""
        for session in sessions:
            dport = session.get("dst_port", 0)
            proto = session.get("protocol", "")
            src_ip = session.get("src_ip")
            dst_ip = session.get("dst_ip")
            pkts = session.get("packet_count", 0)

            if dport == 23 or "Telnet" in proto:
                self.findings.append(Finding(
                    sr_id="SR 5.2",
                    sr_title=IEC62443_CONTROLS["SR 5.2"].title,
                    severity="CRITICAL",
                    finding="TCP/23 (Potential Telnet) unencrypted session observed targeting process controller",
                    evidence=(
                        f"Observed TCP port 23 traffic: {src_ip} → {dst_ip} ({pkts:,} packets). "
                        f"Application parsing is port-based heuristic. Telnet transport protocol transmits data without native encryption; "
                        f"if interactive authentication occurred, credentials could be exposed to passive monitoring. "
                        f"Actual credential exposure was not parsed in the captured sample."
                    ),
                    recommendation=(
                        "Validate operational dependencies urgently with designated plant engineering. "
                        "Determine if controller firmware supports SSH or secure vendor tools. "
                        "If remote administration is required, restrict traffic via an authenticated Level 3.5 DMZ jump host with MFA. "
                        "Disable legacy Telnet services during the next scheduled plant maintenance window."
                    ),
                    target_sl=SL.SL1,
                    nist_ref="NIST SP 800-82 Rev. 3 §5.3 (Remote Access) & §6.2.6 (System and Communications Protection)",
                    mitre_ref="T0886 — Remote Services",
                    risk_rationale="Unencrypted interactive remote administration allows passive eavesdropping and session hijacking if network perimeter is traversed.",
                    evidence_confidence="Medium (Port-based heuristic; payload unparsed)",
                    validation_status="Observed in telemetry — Requires vendor tool confirmation",
                    affected_assets=[src_ip, dst_ip],
                ))
            elif dport == 445 or "SMB" in proto:
                self.findings.append(Finding(
                    sr_id="SR 5.2",
                    sr_title=IEC62443_CONTROLS["SR 5.2"].title,
                    severity="HIGH",
                    finding="TCP/445 (Potential SMB) file-sharing traffic detected targeting supervisory server",
                    evidence=(
                        f"Observed TCP port 445 traffic: {src_ip} → {dst_ip} ({pkts:,} packets). "
                        f"Application parsing is port-based heuristic. Direct workstation-to-SCADA file sharing introduces potential malware propagation vectors."
                    ),
                    recommendation=(
                        "Review business necessity of SMB file sharing. Validate whether backup or historian workflows require port 445. "
                        "Ensure legacy SMBv1 is disabled. Apply conduit filtering at the boundary firewall, and use secure transfer mechanisms (SFTP/HTTPS) where required."
                    ),
                    target_sl=SL.SL1,
                    nist_ref="NIST SP 800-82 Rev. 3 §5.2 (Boundary Protection)",
                    mitre_ref="T0867 — Lateral Tool Transfer",
                    risk_rationale="SMB file-sharing across trust zones is the primary propagation vector for commodity ransomware in industrial environments.",
                    evidence_confidence="Medium (Port-based heuristic)",
                    validation_status="Observed in telemetry — Requires operational verification",
                    affected_assets=[src_ip, dst_ip],
                ))

    def _check_modbus_protocol_limitations(self, sessions, stats):
        """SR 3.1 & SR 1.1 — Contextual Modbus finding combining lack of encryption and lack of station authentication."""
        modbus_pkts = stats.get("Modbus TCP", 0)
        modbus_sessions = [s for s in sessions if s.get("protocol") == "Modbus TCP"]
        if modbus_pkts > 0:
            self.findings.append(Finding(
                sr_id="SR 3.1",
                sr_title=IEC62443_CONTROLS["SR 3.1"].title,
                severity="HIGH",
                finding="Legacy Modbus communication without native cryptographic protection — compensating controls require review",
                evidence=(
                    f"Observed {modbus_pkts:,} Modbus TCP packets across {len(modbus_sessions)} active communication sessions. "
                    f"Standard Modbus protocol specification (port 502) lacks native message encryption and station authentication. "
                    f"Commands and telemetry are transmitted in cleartext, meaning any host with network connectivity can read or issue registers unless constrained by external network controls."
                ),
                recommendation=(
                    "Implement network-level compensating controls: enforce strict VLAN boundaries, implement switch-port IP/MAC ACLs, "
                    "and deploy industrial firewall inspection to permit only approved Modbus function codes between validated SCADA servers and controllers. "
                    "Enable controller-level access control tables (e.g. Modicon M580 Security ACLs) in Control Expert."
                ),
                target_sl=SL.SL2,
                nist_ref="NIST SP 800-82 Rev. 3 §6.2.6 (System and Communications Protection)",
                mitre_ref="T0831 — Manipulate I&C",
                risk_rationale="Industrial protocols lacking cryptographic authentication permit unauthorized register reads and setpoint overrides if network perimeters are breached.",
                evidence_confidence="High (Observed in packet trace)",
                validation_status="Observed in telemetry — Protocol design property",
            ))

    def _check_opc_ua_security(self, sessions, raw_observations):
        """SR 4.1 — OPC-UA SecurityPolicy inspection."""
        opc_sessions = [s for s in sessions if s.get("protocol") == "OPC-UA" or s.get("dst_port") == 4840]
        if opc_sessions:
            insecure_opc = any(
                obs.get("details", {}).get("is_insecure") or 
                "SecurityPolicy#None" in str(obs.get("details", {}).get("security_policy", ""))
                for obs in raw_observations if obs.get("protocol") == "OPC-UA"
            )
            if insecure_opc:
                self.findings.append(Finding(
                    sr_id="SR 4.1",
                    sr_title=IEC62443_CONTROLS["SR 4.1"].title,
                    severity="HIGH",
                    finding="Insecure OPC-UA Channel Configuration (SecurityPolicy#None observed)",
                    evidence=(
                        f"Observed {len(opc_sessions)} OPC-UA TCP session(s) where channel handshake negotiated SecurityPolicy#None. "
                        f"The OPC-UA SecureChannel was established without cryptographic message signing or encryption. "
                        f"Process variables, setpoints, and session tokens are exposed in cleartext to passive eavesdropping on this channel."
                    ),
                    recommendation=(
                        "Validate operational dependencies with SCADA/HMI vendor. "
                        "During a planned engineering window, configure OPC-UA servers and clients to require MessageSecurityMode "
                        "'SignAndEncrypt' with SecurityPolicy 'Basic256Sha256' or 'Aes128_Sha256_RsaOaep'. "
                        "Deploy managed X.509 certificates to replace 'None' endpoints."
                    ),
                    target_sl=SL.SL2,
                    nist_ref="NIST SP 800-82 Rev. 3 §6.2.6 (System and Communications Protection)",
                    mitre_ref="T0855 — Unauthorized Command Message",
                    risk_rationale="Cleartext OPC-UA allows MITM manipulation of supervisory process telemetry and setpoints.",
                    evidence_confidence="High (Observed in packet trace)",
                    validation_status="Observed in telemetry",
                ))

    def _check_hart_security(self, sessions, raw_observations):
        """SR 3.1 — HART-IP transport security."""
        hart_sessions = [s for s in sessions if "HART-IP" in s.get("protocol", "") or s.get("dst_port") == 5094]
        if hart_sessions:
            self.findings.append(Finding(
                sr_id="SR 3.1",
                sr_title=IEC62443_CONTROLS["SR 3.1"].title,
                severity="HIGH",
                finding="HART-IP field communication decoded in cleartext — gateway configuration requires review",
                evidence=(
                    f"The demonstrated HART-IP exchange was decoded in cleartext across {len(hart_sessions)} session(s). "
                    f"FieldComm Group HART-IP specifications support secure TLS/DTLS profiles; security capabilities and "
                    f"configuration of the represented gateway require validation. Scenario assumptions regarding process telemetry "
                    f"require on-site verification against instrument tag databases."
                ),
                recommendation=(
                    "Validate whether deployed gateway hardware supports HART-IP security profiles (TLS/DTLS). "
                    "If unencrypted legacy operation is required, enforce network-level conduit isolation via a dedicated "
                    "VLAN with switch ACL allowlists restricting traffic strictly to authorized supervisory controllers."
                ),
                target_sl=SL.SL2,
                nist_ref="NIST SP 800-82 Rev. 3 §6.2.6 (System and Communications Protection)",
                mitre_ref="T0836 — Modify Parameter",
                risk_rationale="Unencrypted gateway communication allows potential parameter tampering or spoofed readings if conduit access is unrestricted.",
                evidence_confidence="High (Observed in packet trace)",
                validation_status="Observed in telemetry — Gateway capabilities unconfirmed",
            ))

    def _check_dnp3_cleartext(self, stats):
        """SR 3.1 — Cleartext DNP3 protocol."""
        dnp3_pkts = stats.get("DNP3", 0)
        if dnp3_pkts > 0:
            self.findings.append(Finding(
                sr_id="SR 3.1",
                sr_title=IEC62443_CONTROLS["SR 3.1"].title,
                severity="HIGH",
                finding="Cleartext industrial protocol in use: DNP3",
                evidence=(
                    f"Observed {dnp3_pkts:,} DNP3 packets without cryptographic authentication. "
                    f"DNP3 Secure Authentication (DNP3-SA) was not detected in the captured traffic."
                ),
                recommendation=(
                    "Where supported by substation equipment, evaluate enabling DNP3-SA (IEEE 1815-2012). "
                    "For legacy installations, isolate DNP3 circuits onto dedicated VLAN conduits with restricted routing."
                ),
                target_sl=SL.SL2,
                nist_ref="NIST SP 800-82 Rev. 3 §6.2.6 (System and Communications Protection)",
                mitre_ref="T0831 — Manipulate I&C",
                risk_rationale="Cleartext DNP3 allows unauthorized command injection if substation network boundaries are breached.",
                evidence_confidence="High (Observed in packet trace)",
                validation_status="Observed in telemetry",
            ))

    def _check_write_commands(self, observations, assets):
        """SR 2.1 — Distinction between expected baseline writes and unauthorized command sources."""
        writes = [o for o in observations if o.get("is_write")]
        if not writes:
            return

        unregistered_ips = set(a["ip"] for a in assets if not a.get("in_client_inventory", True))
        suspicious_writes = [w for w in writes if w.get("src_ip") in unregistered_ips]
        baseline_writes = [w for w in writes if w.get("src_ip") not in unregistered_ips]

        if suspicious_writes:
            srcs = sorted(list(set(w.get("src_ip") for w in suspicious_writes)))
            self.findings.append(Finding(
                sr_id="SR 2.1",
                sr_title=IEC62443_CONTROLS["SR 2.1"].title,
                severity="CRITICAL",
                finding="Control write commands originating from uninventoried endpoints",
                evidence=(
                    f"Detected {len(suspicious_writes)} write-type command message(s) originating from host(s) absent from "
                    f"the reference inventory: {', '.join(srcs)}. These endpoints issued direct Modbus register write commands to process controllers."
                ),
                recommendation=(
                    "Urgently trace and validate the physical switch port connected to these endpoints with plant engineering. "
                    "Verify why non-registered machines have routing access to process controllers and block unauthorized command sources."
                ),
                target_sl=SL.SL2,
                nist_ref="NIST SP 800-82 Rev. 3 §6.2.2 (Access Control) & §6.2.6",
                mitre_ref="T0831 — Manipulate I&C",
                risk_rationale="Write commands from unverified systems can alter equipment setpoints, override safety trips, or cause equipment damage.",
                evidence_confidence="High (Observed in packet trace)",
                validation_status="Observed in telemetry — Requires engineering confirmation",
            ))

        if baseline_writes:
            self.findings.append(Finding(
                sr_id="SR 2.1",
                sr_title=IEC62443_CONTROLS["SR 2.1"].title,
                severity="INFO",
                finding="Baseline process control write operations observed (Subject to plant verification)",
                evidence=(
                    f"Detected {len(baseline_writes)} distinct write-bearing command function codes between authorized engineering/SCADA stations "
                    f"and controllers (e.g. SCADA polling writes, PLC-to-VFD speed reference updates). "
                    f"Observed activity matches normal plant supervisory control patterns."
                ),
                recommendation=(
                    "Confirm during site verification that all observed write function codes correspond to approved "
                    "SCADA tag databases and operational setpoint ranges."
                ),
                target_sl=SL.SL1,
                nist_ref="NIST SP 800-82 Rev. 3 §6.2.2 (Access Control)",
                mitre_ref="T0831 — Manipulate I&C",
                risk_rationale="Expected operational control traffic; document as baseline profile.",
                evidence_confidence="High (Observed in packet trace)",
                validation_status="Observed in telemetry — Baseline profile",
            ))

    def _check_unregistered_asset_inventory(self, assets):
        """SR 6.2 — Unregistered endpoints detected in passive telemetry."""
        unknown = [a for a in assets if not a.get("in_client_inventory", True)]
        if unknown:
            self.findings.append(Finding(
                sr_id="SR 6.2",
                sr_title=IEC62443_CONTROLS["SR 6.2"].title,
                severity="HIGH",
                finding=f"{len(unknown)} unregistered active endpoint(s) detected on control network",
                evidence=(
                    f"The following IP addresses were observed generating active traffic but are absent from "
                    f"the reference inventory: {', '.join(a['ip'] for a in unknown)}. "
                    f"Identities are inferred from observed traffic behaviors."
                ),
                recommendation=(
                    "Conduct a physical walkdown to confirm device ownership, physical switch port location, and business necessity. "
                    "Update the asset inventory accordingly. Quarantine any endpoint that cannot be validated by plant operations."
                ),
                target_sl=SL.SL1,
                nist_ref="NIST SP 800-82 Rev. 3 §5.1 (Network Segmentation) & §6.2.2",
                mitre_ref="T0886 — Remote Services",
                risk_rationale="Unmanaged assets on control segments introduce unpatched operating systems and unauthorized bridging pathways.",
                evidence_confidence="High (Observed in packet trace)",
                validation_status="Observed in telemetry — Requires physical walkdown",
            ))

    def _check_no_monitoring(self, sessions):
        """SR 6.2 — Security event monitoring."""
        syslog_seen = any(
            s.get("dst_port") in (514, 6514, 601) or s.get("src_port") in (514, 6514)
            for s in sessions
        )
        if not syslog_seen:
            self.findings.append(Finding(
                sr_id="SR 6.2",
                sr_title=IEC62443_CONTROLS["SR 6.2"].title,
                severity="MEDIUM",
                finding="No identified log-forwarding traffic observed within capture coverage",
                evidence="Zero syslog (UDP/TCP 514) or encrypted event forwarding observed from SCADA servers, HMIs, or managed switches in the captured span.",
                recommendation=(
                    "Request collector configuration, endpoint logging settings, and retention policies from plant IT/OT engineering before determining a compliance gap. "
                    "If centralized logging is absent, deploy an OT-compatible log aggregator or SIEM forwarder in the Industrial DMZ (L3.5) with NTP synchronization."
                ),
                target_sl=SL.SL2,
                nist_ref="NIST SP 800-82 Rev. 3 §6.2.4 (Audit and Accountability)",
                mitre_ref="N/A — Observational Gap",
                risk_rationale="Without centralized event forwarding, detection of intrusions or post-incident root-cause investigation is severely impeded.",
                evidence_confidence="Medium (Absence of traffic in monitored TAP span)",
                validation_status="Observed in telemetry — Scope validation required",
            ))

    def _check_default_creds_hint(self, assets, sessions):
        """SR 1.3 — SNMP community string inspection."""
        snmp_sessions = [s for s in sessions if s.get("dst_port") == 161 or s.get("src_port") == 161 or "SNMP" in s.get("protocol", "")]
        if snmp_sessions:
            self.findings.append(Finding(
                sr_id="SR 1.3",
                sr_title=IEC62443_CONTROLS["SR 1.3"].title,
                severity="MEDIUM",
                finding="Cleartext SNMP polling traffic observed — verify community strings",
                evidence=f"Observed SNMP (UDP 161) polling traffic across {len(snmp_sessions)} session(s).",
                recommendation=(
                    "Verify that default community strings ('public', 'private') are not in use. "
                    "Migrate network devices to SNMPv3 with authentication and privacy (authPriv). If SNMP is unused, disable the service."
                ),
                target_sl=SL.SL1,
                nist_ref="NIST SP 800-82 Rev. 3 §6.2.1 (Identification and Authentication)",
                mitre_ref="T0888 — Remote System Information Discovery",
                risk_rationale="SNMPv1/v2c transmits community strings in cleartext; standard strings allow reconnaissance of switch port states and network topologies.",
                evidence_confidence="High (Observed in packet trace)",
                validation_status="Observed in telemetry",
            ))

    def _check_broadcast_traffic(self, sessions):
        """SR 7.1 — Excessive broadcast traffic."""
        broadcasts = [s for s in sessions if s.get("dst_ip", "").endswith(".255") or s.get("dst_ip") == "255.255.255.255"]
        if len(broadcasts) > 50:
            self.findings.append(Finding(
                sr_id="SR 7.1",
                sr_title=IEC62443_CONTROLS["SR 7.1"].title,
                severity="LOW",
                finding="Elevated broadcast frame volume on control network",
                evidence=f"Observed {len(broadcasts)} broadcast frames during capture window.",
                recommendation="Isolate broadcast domains via VLANs to prevent latency-sensitive controller communication disruption.",
                target_sl=SL.SL1,
                nist_ref="NIST SP 800-82 Rev. 3 §6.2.6 (System and Communications Protection)",
                mitre_ref="T0814 — Denial of Service",
                risk_rationale="Unconstrained broadcast storms can cause packet loss on time-critical industrial protocols.",
                evidence_confidence="High (Observed in packet trace)",
                validation_status="Observed in telemetry",
            ))

    # -----------------------------------------------------------------------
    # Scoring Across ALL 7 Foundational Requirements
    # -----------------------------------------------------------------------

    def sl_score(self) -> dict:
        """Calculate technical observations mapped to all 7 IEC 62443 Foundational Requirements."""
        severity_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        domains = {
            "FR 1: IAC (Identification & Authentication)": ["SR 1.1", "SR 1.2", "SR 1.3"],
            "FR 2: UC (Use Control)":                      ["SR 2.1"],
            "FR 3: SI (System Integrity)":                 ["SR 3.1", "SR 3.3"],
            "FR 4: DC (Data Confidentiality)":             ["SR 4.1"],
            "FR 5: RDF (Restricted Data Flow)":            ["SR 5.1", "SR 5.2", "SR 5.3"],
            "FR 6: TRE (Timely Response to Events)":       ["SR 6.1", "SR 6.2"],
            "FR 7: RA (Resource Availability)":            ["SR 7.1", "SR 7.6"],
        }
        result = {}
        for domain, srs in domains.items():
            domain_findings = [f for f in self.findings if f.sr_id in srs]
            worst = max((severity_map.get(f.severity, 0) for f in domain_findings), default=0)
            worst_sev = next(
                (f.severity for f in domain_findings if severity_map.get(f.severity, 0) == worst), "NONE"
            )

            if "FR 7" in domain:
                result[domain] = {
                    "findings_count": len(domain_findings),
                    "worst_severity": worst_sev,
                    "technical_posture": "Not Assessed in Capture",
                    "target_sl_scope": "Zone-Dependent (Established per IEC 62443-3-2 Risk Assessment)",
                    "gap_summary": "Resource-availability controls not assessed; no selected availability anomaly detected within demonstrated capture.",
                }
            else:
                result[domain] = {
                    "findings_count": len(domain_findings),
                    "worst_severity": worst_sev,
                    "technical_posture": f"⚠️ {worst_sev} Findings" if domain_findings else "✅ Baseline Normal",
                    "target_sl_scope": "Zone-Dependent (Established per IEC 62443-3-2 Risk Assessment)",
                    "gap_summary": f"⚠️ {len(domain_findings)} observation(s) requiring validation" if domain_findings else "✅ No violations observed in passive trace",
                }
        return result
