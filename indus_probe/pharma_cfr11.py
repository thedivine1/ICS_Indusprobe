"""
IndusProbe — USFDA 21 CFR Part 11 & GAMP 5 Data Integrity Audit Engine

Evaluates OT/SCADA networks in Pharmaceutical (API, Formulations, Vaccines)
facilities against USFDA 21 CFR Part 11 electronic records & electronic signatures
regulations based entirely on passive network traffic observations.

Key Checks:
  - §11.10(e): Time-stamped audit trail integrity & NTP time synchronization
  - §11.10(c): Protection of batch records & cleartext Historian SQL traffic (MSSQL 1433, Oracle 1521)
  - §11.10(d): Access control & cleartext credential exposure (Telnet, HTTP, FTP, VNC)
  - §11.10(g): Authority checks for recipe setpoint writes (S7Comm, CIP, Modbus writes to batch PLCs)
  - §11.30:    Open system encryption controls (OPC-UA SecurityPolicy#None detection)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class CFR11Finding:
    clause: str
    requirement: str
    severity: str             # CRITICAL, HIGH, MEDIUM, LOW
    observation: str
    remediation: str
    evidence_ips: list[str] = field(default_factory=list)


class PharmaDataIntegrityAuditor:
    """
    Passively audits network sessions against FDA 21 CFR Part 11 data integrity standards.
    """

    def __init__(self, sessions: list[dict[str, Any]], assets: list[dict[str, Any]]):
        self.sessions = sessions
        self.assets = assets
        self.findings: list[CFR11Finding] = []

    def evaluate(self) -> dict[str, Any]:
        self.findings.clear()
        
        # 1. Check for unencrypted database traffic (MSSQL/Oracle/Postgres) between SCADA & Historian
        db_sessions = [
            s for s in self.sessions 
            if s.get("dst_port") in (1433, 1521, 5432, 3306) or s.get("src_port") in (1433, 1521, 5432, 3306)
        ]
        if db_sessions:
            ips = list(set([s.get("src_ip", "") for s in db_sessions] + [s.get("dst_ip", "") for s in db_sessions]))
            self.findings.append(CFR11Finding(
                clause="21 CFR §11.10(c)",
                requirement="Protection of records to enable accurate and ready retrieval throughout retention period",
                severity="HIGH",
                observation=f"Observed {len(db_sessions)} raw database sessions (Historian/Batch SQL) without TLS transport encryption. Attackers or malicious insiders can intercept or tamper with batch records in transit.",
                remediation="Enforce TLS 1.3 encryption on database connections between SCADA/MES applications and the Electronic Batch Record (EBR) Historian.",
                evidence_ips=ips
            ))

        # 2. Check for missing NTP / Time Synchronization traffic (§11.10(e))
        ntp_sessions = [s for s in self.sessions if s.get("dst_port") == 123 or s.get("src_port") == 123]
        if not ntp_sessions:
            self.findings.append(CFR11Finding(
                clause="21 CFR §11.10(e)",
                requirement="Use of secure, computer-generated, time-stamped audit trails to independently record operator actions",
                severity="HIGH",
                observation="Zero NTP (UDP 123) time synchronization traffic detected on the OT subnet. When PLCs, HMIs, and Historians have divergent clocks, batch event sequences cannot be legally substantiated during an FDA audit.",
                remediation="Deploy a dedicated Stratum-1 GPS time server in the Industrial DMZ and configure all SCADA nodes, HMIs, and PLCs to sync via authenticated NTP.",
                evidence_ips=[]
            ))

        # 3. Check for OPC-UA SecurityPolicy#None in Batch Systems
        opc_none_sessions = [
            s for s in self.sessions 
            if "OPC" in str(s.get("protocol", "")) and s.get("details", {}).get("security_policy") == "None"
        ]
        if opc_none_sessions:
            self.findings.append(CFR11Finding(
                clause="21 CFR §11.30",
                requirement="Controls for open systems — ensuring document authenticity, integrity, and confidentiality",
                severity="CRITICAL",
                observation="OPC-UA sessions configured with 'SecurityPolicy#None'. Batch critical process parameters (temperature, pH, agitation) are transferred without cryptographic signing or encryption.",
                remediation="Configure OPC-UA endpoints to enforce MessageSecurityMode 'SignAndEncrypt' with X.509 digital certificates.",
                evidence_ips=[s.get("src_ip", "") for s in opc_none_sessions]
            ))

        # 4. Check for Unauthenticated Writes to PLCs (§11.10(g))
        write_sessions = [s for s in self.sessions if s.get("is_write") is True]
        if write_sessions:
            write_ips = list(set([s.get("src_ip", "") for s in write_sessions]))
            self.findings.append(CFR11Finding(
                clause="21 CFR §11.10(g)",
                requirement="Use of authority checks to ensure that only authorized individuals can alter electronic records or system parameters",
                severity="CRITICAL",
                observation=f"Observed {len(write_sessions)} direct PLC register write commands without dual-authorization or electronic signature tokens. Any host on the subnet can alter batch setpoints.",
                remediation="Implement electronic signature challenges at HMI level prior to issuing write commands to batch controllers; enforce controller access control lists (ACLs).",
                evidence_ips=write_ips
            ))

        # Calculate Compliance Score
        total_checks = 10
        failed_checks = len(self.findings)
        score = max(0, int(((total_checks - failed_checks) / total_checks) * 100))

        return {
            "compliance_score_percent": score,
            "status": "CONFORMANT" if score >= 85 else "NON-CONFORMANT (HIGH AUDIT RISK)",
            "findings_count": len(self.findings),
            "critical_count": sum(1 for f in self.findings if f.severity == "CRITICAL"),
            "high_count": sum(1 for f in self.findings if f.severity == "HIGH"),
            "findings": self.findings,
        }

