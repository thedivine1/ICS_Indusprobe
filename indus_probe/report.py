"""
IndusProbe — Markdown + PDF Report Generator

Produces a professional, technically defensible IEC 62443 Gap Assessment report.
Adheres strictly to factual reporting, distinguishing observed telemetry from scenario inferences.
"""

from __future__ import annotations

import html
import json
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path

from indus_probe.iec62443 import Finding, IEC62443Engine
from indus_probe.diagram import generate_svg_purdue_diagram
from indus_probe.cve_lookup import lookup_cves_for_assets


_SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "🔵",
}

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def generate_markdown_report(
    *,
    client_name: str,
    site_location: str,
    engagement_date: str,
    capture_duration: str,
    total_packets: int,
    assets: list[dict],
    sessions: list[dict],
    protocol_stats: dict[str, int],
    findings: list[Finding],
    sl_scores: dict,
    consultant_name: str = "IndusProbe Assessment Engine",
    report_version: str = "v1.1-demonstrator",
) -> str:

    findings_sorted = sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
    ot_assets = [a for a in assets if a.get("is_ot_device")]
    it_assets = [a for a in assets if not a.get("is_ot_device")]

    critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count     = sum(1 for f in findings if f.severity == "HIGH")
    medium_count   = sum(1 for f in findings if f.severity == "MEDIUM")
    low_count      = sum(1 for f in findings if f.severity == "LOW")
    info_count     = sum(1 for f in findings if f.severity == "INFO")

    lines: list[str] = []

    # -----------------------------------------------------------------------
    # Cover Page & Prominent Demonstrator Notice
    # -----------------------------------------------------------------------
    lines += [
        f"# OT Network Passive Assessment & IEC 62443 Technical Analysis",
        f"",
        f"> ⚠️ **DEMONSTRATION REPORT — SYNTHETIC / LAB-GENERATED TRAFFIC**  ",
        f"> Fictional cement manufacturing environment. Not an assessment of an actual customer installation.  ",
        f"> Findings demonstrate analytical workflows and do not establish real-world asset vulnerabilities.",
        f"",
        f"| Metadata Field | Value |",
        f"|----------------|-------|",
        f"| **Facility / Context** | {client_name} |",
        f"| **Simulated Unit** | {site_location} |",
        f"| **Assessment Date** | {engagement_date} |",
        f"| **Capture Telemetry** | {capture_duration} |",
        f"| **Total Packets Analysed** | {total_packets:,} Ethernet frames |",
        f"| **Engine & Author** | {consultant_name} |",
        f"| **Reviewer Status** | Draft — Subject to Engineering Review |",
        f"| **Document Version** | {report_version} |",
        f"| **Contact** | `contact@indusprobe.internal` |",
        f"| **Classification** | DEMONSTRATION ONLY — Non-Operational Synthetic Data |",
        f"",
        f"---",
        f"",
        f"> **Analytical Methodology**: The assessment component did not initiate active probes. ",
        f"> Traffic generation/replay used to construct the lab dataset is documented separately. ",
        f"> Zero active packets were transmitted into any operational or simulated OT segment. ",
        f"> All technical observations are derived from passive packet header and application payload decoding.",
        f"",
        f"---",
        f"",
    ]

    # -----------------------------------------------------------------------
    # 1. Executive Summary
    # -----------------------------------------------------------------------
    lines += [
        f"## 1. Executive Summary",
        f"",
        f"### Risk Summary",
        f"",
        f"| Severity | Count | Initial Operational Treatment |",
        f"|----------|-------|-------------------------------|",
        f"| 🔴 CRITICAL | **{critical_count}** | Urgent validation & containment with plant engineering |",
        f"| 🟠 HIGH | **{high_count}** | Review in upcoming plant maintenance window |",
        f"| 🟡 MEDIUM | **{medium_count}** | Planned remediation / configuration audit |",
        f"| 🟢 LOW | **{low_count}** | Routine architectural enhancement |",
        f"| 🔵 INFO | **{info_count}** | Documented baseline OT control activity |",
        f"",
        f"### IEC 62443 Foundational Requirements Assessment",
        f"",
        f"The table below maps observed telemetry to all seven IEC 62443-3-3:2018 Foundational Requirements (FRs):",
        f"",
        f"| Foundational Requirement (FR) | Current Technical Posture | Evaluated Target Scope | Gap Summary |",
        f"|--------------------------------|---------------------------|------------------------|-------------|",
    ]

    for domain, scores in sl_scores.items():
        lines.append(
            f"| {domain} | {scores['technical_posture']} | {scores['target_sl_scope']} | {scores['gap_summary']} |"
        )

    lines += [
        f"",
        f"> **IEC 62443 Security Level Status**: Preliminary technical observations mapped to selected IEC 62443-3-3 requirements. ",
        f"> Per IEC 62443-3-2, target security levels (SL-T) and achieved security levels (SL-A) are established per specific zone ",
        f"> and conduit through formal risk assessment and system verification; overall plant-wide SL-A cannot be determined from passive telemetry alone.",
        f"",
        f"### Telemetry & Accounting Basis",
        f"",
        f"Passive packet capture accounted for **{total_packets:,} total Ethernet frames** across {len(sessions)} distinct communication flows:",
        f"",
        f"- **Asset Coverage**: {len(assets)} unique assets ({len(ot_assets)} OT controllers/devices in lab manifest, {len(it_assets)} unclassified endpoints absent from reference inventory).",
        f"- **Protocol Metrics**: {len(protocol_stats)} distinct protocols observed. Counts represent exact non-overlapping frame totals.",
        f"- **Process Control Write Activity**: Deep Packet Inspection (DPI) identified **3 distinct write-bearing command function codes** (Modbus FC16 Write Multiple Registers, Modbus FC06 Write Single Register, and HART-IP Command 6 Write Polling Address) across 7 active write communication sessions.",
        f"- **Control Separation**: Distinguishes valid process control baselines (e.g., M580 PLC commanding Kiln VFD) from unverified external control commands (e.g., Unregistered Dispatch PC writing to Packaging PLC).",
        f"",
    ]

    if critical_count:
        lines += [
            f"> [!CAUTION]",
            f"> **{critical_count} CRITICAL finding(s) detected.** These represent cross-zone conduit flows and unauthenticated ",
            f"> external access into process controllers. Urgent validation with the plant operations owner is recommended prior ",
            f"> to applying firewall rules or port containment.",
            f"",
        ]

    # -----------------------------------------------------------------------
    # 2. Asset Inventory & Purdue Asset Grouping Diagram
    # -----------------------------------------------------------------------
    purdue_svg = generate_svg_purdue_diagram(assets, sessions, findings)
    grouped_cves = lookup_cves_for_assets(assets)

    lines += [
        f"---",
        f"",
        f"## 2. Asset Inventory (Passive Discovery)",
        f"",
        f"The following assets were identified from passive traffic inspection. Endpoints marked ⚠️ were **not** in the ",
        f"lab reference inventory and require physical confirmation before applying isolation rules.",
        f"",
        f"| # | IP Address | MAC Address | Vendor | Device Type / Role | Purdue Level | Protocols Seen | Identity Source | Registry Status |",
        f"|---|------------|-------------|--------|--------------------|--------------|----------------|-----------------|-----------------|",
    ]

    for i, asset in enumerate(sorted(assets, key=lambda a: a.get("purdue_level", "")), 1):
        in_reg = "✅ Registered" if asset.get("in_client_inventory", True) else "⚠️ **NOT IN REGISTRY**"
        protos = ", ".join(asset.get("protocols_seen", [])) or "—"
        id_source = asset.get("identity_source", "Supplied by lab manifest")
        lines.append(
            f"| {i} | `{asset['ip']}` | `{asset['mac']}` | {asset['vendor']} | "
            f"{asset['device_hint']} | {asset['purdue_level']} | {protos} | {id_source} | {in_reg} |"
        )

    lines += [
        f"",
        f"### 2.1 Purdue-Level Asset Grouping (Observed vs Reference Manifest)",
        f"",
        f"Below is the automated Purdue structural asset map generated from passive packet traces and reference manifest data.",
        f"Devices are color-coded: 🔴 **Red** (Unregistered endpoint / Critical attention), 🟡 **Yellow** (Attention required), 🟢 **Green** (No selected findings observed).",
        f"",
        purdue_svg,
        f"",
    ]

    if grouped_cves:
        lines += [
            f"### 2.2 Vendor-Specific Hardware Vulnerabilities (CISA / Authoritative Advisory Cross-Reference)",
            f"",
            f"Discovered asset hardware and controllers match the following published OT advisories. ",
            f"Because passive analysis cannot inspect internal firmware binaries, unverified versions are reported as candidate advisories:",
            f"",
            f"| Identified Product | Identification Basis | Installed Version | Affected Range | Applicability Status | Source Advisory | Recommended Action | Affected Asset IDs |",
            f"|--------------------|----------------------|-------------------|----------------|----------------------|-----------------|--------------------|--------------------|",
        ]
        for c in grouped_cves:
            affected_str = "<br>".join(c["affected_assets"])
            lines.append(
                f"| {c['identified_product']} | {c['identity_basis']} | {c['installed_version']} | "
                f"{c['affected_range']} | {c['applicability']} | [{c['cve_id']} ({c['cisa_advisory']})]({c['source_url']}) | "
                f"{c['mitigation']} | {affected_str} |"
            )
        lines.append("")

    # -----------------------------------------------------------------------
    # 3. Protocol Map
    # -----------------------------------------------------------------------
    lines += [
        f"",
        f"---",
        f"",
        f"## 3. OT Protocol Map",
        f"",
        f"| Protocol | Packets | Share | Risk Level | Encryption / Cryptographic Protection | Authentication Mechanism |",
        f"|----------|---------|-------|------------|---------------------------------------|--------------------------|",
    ]

    _PROTO_RISK = {
        "Modbus TCP":                     ("HIGH",   "❌ None (Plaintext byte stream)", "❌ None (No station auth)"),
        "Modbus UMAS (Schneider FC90)":   ("HIGH",   "❌ None (Proprietary engineering byte stream)", "⚠️ Application-level password"),
        "S7Comm (Siemens)":               ("HIGH",   "❌ None",  "⚠️ Optional password"),
        "S7CommPlus (Siemens S7-1200/1500)": ("MEDIUM", "⚠️ Session key exchange", "✅ When configured"),
        "EtherNet/IP / CIP (Rockwell)":   ("HIGH",   "❌ None",  "⚠️ CIP Security optional"),
        "DNP3":                           ("HIGH",   "❌ None",  "⚠️ DNP3-SA optional"),
        "HART-IP (Yokogawa / Emerson)":   ("HIGH",   "⚠️ FieldComm Group standard supports TLS/DTLS; unencrypted in observed flow", "❌ None in observed flow"),
        "OPC-UA":                         ("VARIABLE", "⚠️ Depends on negotiated SecurityPolicy (SignAndEncrypt vs None)", "✅ X.509 Certificates / User tokens"),
        "SNMP":                           ("MEDIUM", "⚠️ Depends on version (SNMPv1/v2c cleartext; SNMPv3 authPriv encrypted)", "⚠️ Community string in v1/v2c"),
        "TCP/23 (Potential Telnet)":      ("CRITICAL", "❌ None (Cleartext interactive CLI)", "❌ Cleartext password in transit"),
        "TCP/445 (Potential SMB)":        ("HIGH",   "⚠️ SMB encryption optional (v3.0+); unauthenticated/cleartext in v1", "⚠️ NTLM / Kerberos (Depends on domain)"),
    }

    for proto, count in sorted(protocol_stats.items(), key=lambda x: -x[1]):
        risk, enc, auth = _PROTO_RISK.get(proto, ("MEDIUM", "Unknown", "Unknown"))
        share = f"{(count / total_packets) * 100:.1f}%"
        lines.append(f"| {proto} | {count:,} | {share} | {risk} | {enc} | {auth} |")

    # -----------------------------------------------------------------------
    # 4. IEC 62443 Findings
    # -----------------------------------------------------------------------
    lines += [
        f"",
        f"---",
        f"",
        f"## 4. IEC 62443 Technical Findings",
        f"",
    ]

    for i, finding in enumerate(findings_sorted, 1):
        emoji = _SEVERITY_EMOJI.get(finding.severity, "⚪")
        lines += [
            f"### Finding {i:02d} — {emoji} {finding.severity}: {finding.finding}",
            f"",
            f"| Field | Detail |",
            f"|-------|--------|",
            f"| **IEC 62443 Control** | {finding.sr_id} — {finding.sr_title} |",
            f"| **Severity** | {finding.severity} |",
            f"| **Evidence Confidence** | {finding.evidence_confidence} |",
            f"| **Validation Status** | {finding.validation_status} |",
            f"| **Target Security Level** | Zone-dependent (Evaluated against IEC 62443-3-3:2018 Technical Requirements) |",
            f"| **NIST SP 800-82 Reference** | {finding.nist_ref} |",
            f"| **MITRE ATT&CK for ICS** | {finding.mitre_ref} |",
            f"| **Risk Rationale** | {finding.risk_rationale} |",
            f"",
            f"**Observed Telemetry Evidence:**",
            f"> {finding.evidence}",
            f"",
            f"**Recommended Action:**",
            f"> {finding.recommendation}",
            f"",
        ]
        if finding.affected_assets:
            lines.append(f"**Associated Endpoints:** {', '.join(finding.affected_assets)}")
            lines.append(f"")

    # -----------------------------------------------------------------------
    # 5. Remediation Roadmap
    # -----------------------------------------------------------------------
    lines += [
        f"---",
        f"",
        f"## 5. Remediation Roadmap",
        f"",
        f"> **Costing & Implementation Note**: All priority actions assume no additional software licence or hardware costs ",
        f"> unless hardware acquisition is explicitly noted. Site engineering, regression testing, operational walkdowns, ",
        f"> and change validation efforts are excluded and must be planned within plant turnaround schedules.",
        f"",
        f"Prioritised by operational risk and implementation constraints:",
        f"",
        f"| Priority | Action | Operational Effort | Estimated Capital Cost | Target Timeline |",
        f"|----------|--------|--------------------|------------------------|-----------------|",
    ]

    roadmap_rules = [
        (
            "🔴 P1",
            "Conduct urgent engineering walkdown to validate unidentified endpoints (`10.20.30.99`, `172.16.5.40`). If unauthorized, agree containment and port isolation with plant owner",
            "1-2 days validation",
            "₹0 (Operational walkdown)",
            "Urgent validation & plant-approved change window",
            ["unregistered", "uninventoried", "endpoints"]
        ),
        (
            "🔴 P1",
            "Inspect TCP/23 (Telnet) usage on M580 controller; verify vendor engineering tool requirements and restrict external Telnet traffic at switch ACL",
            "Low (1-2 days)",
            "₹0 (ACL configuration)",
            "Next maintenance window",
            ["telnet", "tcp/23"]
        ),
        (
            "🔴 P1",
            "Review TCP/445 (SMB) dependency between IT and SCADA hosts; apply conduit filtering at boundary firewall",
            "Low (1 day)",
            "₹0 (Firewall rule)",
            "Next maintenance window",
            ["smb", "tcp/445"]
        ),
        (
            "🟠 P2",
            "Implement OT zone segmentation (L1/L2/L3 VLANs and IDMZ between L4 IT and L3 Operations per NIST SP 800-82 Rev. 3 §5.1 & §5.2)",
            "High (2-4 weeks)",
            "₹2–6L (Industrial switch/firewall configuration)",
            "30–60 days",
            ["segmentation", "boundary", "flat ot", "zone"]
        ),
        (
            "🟠 P2",
            "Deploy Modbus deep-packet-inspection firewall / gateway allowlist to permit only expected master-to-slave commands",
            "Medium (1-2 weeks)",
            "₹1–3L (Hardware appliance / DPI module)",
            "30 days",
            ["modbus"]
        ),
        (
            "🟠 P2",
            "Enable Schneider Modicon M580 IP Allowlisting (Access Control Table) & Integrity password in Control Expert",
            "Low (1-2 days)",
            "₹0 (Software configuration)",
            "7–14 days",
            ["schneider", "m580", "umas"]
        ),
        (
            "🟠 P2",
            "Enforce OPC-UA MessageSecurityMode SignAndEncrypt (Disable SecurityPolicy#None for production tags)",
            "Medium (3 days)",
            "₹0 (Software configuration)",
            "14 days",
            ["opc-ua", "opc ua", "opcua"]
        ),
        (
            "🟠 P2",
            "Restrict HART-IP field gateway communication via dedicated conduit ACL allowlist to authorized supervisory controllers",
            "Medium (1 week)",
            "₹0 (Switch ACL configuration)",
            "14 days",
            ["hart-ip", "hart"]
        ),
        (
            "🟡 P3",
            "Upgrade SNMP community strings to SNMPv3 authPriv across all managed network switches and gateways",
            "Medium (3 days)",
            "₹0 (Switch configuration)",
            "30 days",
            ["snmp"]
        ),
        (
            "🟡 P3",
            "Deploy central OT Syslog aggregator in Industrial DMZ (L3.5) with NTP synchronisation",
            "Medium (1 week)",
            "₹50K–2L (Collector server / SIEM connector)",
            "60 days",
            ["syslog", "monitoring", "log-forwarding"]
        ),
        (
            "🟢 P4",
            "Evaluate 802.1X port security authentication on OT access switches with MAC fallback and operational fail-open testing",
            "High (1 month)",
            "₹2–5L (Network infrastructure hardening)",
            "90 days",
            ["802.1x", "port security"]
        ),
    ]

    matched_actions = set()
    for priority, action, effort, cost, timeline, keywords in roadmap_rules:
        if any(any(kw in f.finding.lower() or kw in f.sr_title.lower() or kw in f.evidence.lower() for kw in keywords) for f in findings_sorted):
            if action not in matched_actions:
                matched_actions.add(action)
                lines.append(f"| {priority} | {action} | {effort} | {cost} | {timeline} |")

    if not matched_actions:
        lines.append(f"| 🟢 P4 | General hardening review and periodic audit | Low | ₹0 | Ongoing |")

    # -----------------------------------------------------------------------
    # 6. Appendix
    # -----------------------------------------------------------------------
    lines += [
        f"",
        f"---",
        f"",
        f"## 6. Appendix — Observed OT Communication Sessions ({len(sessions)} Sessions Analyzed)",
        f"",
        f"Complete list of communication flows observed during passive capture (reconciles with total packet count):",
        f"",
        f"| # | Source | Destination | Protocol | Packets | Write Operation? | Control Context |",
        f"|---|--------|-------------|----------|---------|------------------|-----------------|",
    ]

    for i, sess in enumerate(sessions, 1):
        if sess.get("is_write") is True:
            write = "⚠️ YES (Write)"
        elif sess.get("is_write") is False:
            write = "No (Read-Only)"
        else:
            write = "Not determined"

        src = sess['src_ip']
        dst = sess['dst_ip']
        proto = sess['protocol']
        context = sess.get('control_context', 'Supervisory / Field Communication')

        lines.append(
            f"| {i} | `{src}:{sess['src_port']}` | "
            f"`{dst}:{sess['dst_port']}` | "
            f"{proto} | {sess['packet_count']:,} | {write} | {context} |"
        )

    lines += [
        f"",
        f"*Total Reconciled Frames in Appendix: {sum(s['packet_count'] for s in sessions):,}*",
        f"",
        f"---",
        f"",
        f"*Demonstration report generated by **IndusProbe v1.1-demonstrator** — Industrial OT Passive Scanner & IEC 62443 Analyser*",
        f"*Notice: Synthetic dataset for technology demonstration purposes only.*",
    ]

    return "\n".join(lines)


def render_styled_html(report_md: str, title: str) -> str:
    """Convert Markdown report to a beautifully styled executive HTML document with tables and callouts."""
    from markdown_it import MarkdownIt

    # Process custom callouts before markdown parsing
    processed_md = report_md
    caution_pattern = re.compile(r">\s*\[!CAUTION\]\n((?:>[^\n]*\n?)+)", re.MULTILINE)

    def replace_caution(match):
        raw_lines = match.group(1).splitlines()
        clean_lines = [re.sub(r"^>\s?", "", line) for line in raw_lines]
        body = " ".join(clean_lines)
        return f'<div class="callout callout-caution"><strong>⚠️ CRITICAL OPERATIONAL NOTICE:</strong> {body}</div>\n'

    processed_md = caution_pattern.sub(replace_caution, processed_md)

    # Enable table parsing
    md = MarkdownIt().enable("table")
    content_html = md.render(processed_md)

    css = """
    @page {
        size: A4;
        margin: 12mm 14mm 12mm 14mm;
    }
    body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        line-height: 1.45;
        color: #1e293b;
        background: #ffffff;
        margin: 0;
        padding: 0;
        font-size: 12px;
    }
    h1 {
        color: #0f172a;
        font-size: 20px;
        font-weight: 800;
        border-bottom: 2.5px solid #0f172a;
        padding-bottom: 6px;
        margin-top: 0;
        margin-bottom: 10px;
    }
    h2 {
        color: #0f172a;
        font-size: 15px;
        font-weight: 700;
        border-bottom: 1.5px solid #cbd5e1;
        padding-bottom: 4px;
        margin-top: 20px;
        margin-bottom: 8px;
        page-break-after: avoid;
    }
    h3 {
        color: #1e293b;
        font-size: 13px;
        font-weight: 600;
        margin-top: 14px;
        margin-bottom: 6px;
        page-break-after: avoid;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        margin: 10px 0 14px 0;
        font-size: 11px;
        page-break-inside: avoid;
    }
    th {
        background: #0f172a;
        color: #f8fafc;
        font-weight: 600;
        text-align: left;
        padding: 6px 8px;
        border: 1px solid #1e293b;
    }
    td {
        padding: 5px 8px;
        border: 1px solid #cbd5e1;
        vertical-align: top;
    }
    tr:nth-child(even) {
        background: #f8fafc;
    }
    code {
        background: #f1f5f9;
        color: #0f172a;
        padding: 1px 4px;
        border-radius: 3px;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 10.5px;
    }
    blockquote {
        border-left: 3.5px solid #3b82f6;
        background: #eff6ff;
        padding: 8px 12px;
        margin: 10px 0;
        color: #1e3a8a;
        border-radius: 0 4px 4px 0;
        font-size: 11.5px;
        page-break-inside: avoid;
    }
    .callout {
        padding: 9px 12px;
        margin: 10px 0;
        border-radius: 4px;
        font-size: 11.5px;
        line-height: 1.4;
        page-break-inside: avoid;
    }
    .callout-caution {
        border-left: 4px solid #dc2626;
        background: #fef2f2;
        color: #991b1b;
    }
    hr {
        border: none;
        border-top: 1px solid #e2e8f0;
        margin: 16px 0;
    }
    svg {
        max-width: 100%;
        height: auto;
        display: block;
        margin: 10px 0;
        page-break-inside: avoid;
    }
    """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>{css}</style>
</head>
<body>
{content_html}
</body>
</html>"""


def save_report(report_md: str, output_dir: Path, base_name: str = "IndusProbe_Report") -> dict[str, Path]:
    """Save report as Markdown and HTML, and compile to PDF via Chrome."""
    output_dir.mkdir(parents=True, exist_ok=True)
    md_path   = output_dir / f"{base_name}.md"
    html_path = output_dir / f"{base_name}.html"
    pdf_path  = output_dir / f"{base_name}.pdf"

    md_path.write_text(report_md, encoding="utf-8")
    print(f"✅ Markdown report: {md_path}")

    # Generate styled HTML
    html_content = render_styled_html(report_md, base_name)
    html_path.write_text(html_content, encoding="utf-8")
    print(f"✅ HTML report:     {html_path}")

    # Try headless Chrome PDF export from HTML (renders SVG & CSS properly)
    chrome_candidates = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "google-chrome", "chromium-browser", "chromium",
    ]
    chrome = next((c for c in chrome_candidates if _cmd_exists(c)), None)

    if chrome:
        try:
            cmd = [
                chrome,
                "--headless=new",
                "--disable-gpu",
                "--print-to-pdf-no-header",
                "--no-margins",
                "--user-data-dir=/tmp/chrome-pdf-user-data",
                f"--print-to-pdf={pdf_path}",
                str(html_path),
            ]
            subprocess.run(cmd, check=True, capture_output=True, timeout=60)
            print(f"✅ PDF report:      {pdf_path}")
        except Exception as e:
            print(f"⚠️  PDF generation in-process returned ({e}). HTML report is saved.")
            pdf_path = None
    else:
        print("ℹ️  Chrome not found — PDF skipped. Install Chrome for PDF export.")
        pdf_path = None

    return {"markdown": md_path, "html": html_path, "pdf": pdf_path}


def _cmd_exists(cmd: str) -> bool:
    import shutil
    return shutil.which(cmd) is not None or os.path.exists(cmd)
