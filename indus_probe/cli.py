"""
IndusProbe — CLI Entry Point

Usage:
  indus-probe pcap  --file capture.pcap --client "ABC Manufacturing" --site "Pune Plant"
  indus-probe live  --interface eth1 --duration 172800  (48 hours)
  indus-probe demo  (runs against a built-in sample to verify everything works)
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("indus_probe")

BANNER = r"""
╔══════════════════════════════════════════════════════╗
║          IndusProbe v1.0 — OT Passive Scanner        ║
║      IEC 62443 Gap Assessment & Reporting Tool       ║
║                                                      ║
║  ⚠  PASSIVE LISTEN-ONLY — ZERO PACKETS TRANSMITTED  ║
║  Supports: Siemens · Rockwell · Schneider · GE       ║
║            Yokogawa · ABB · Honeywell · Emerson      ║
╚══════════════════════════════════════════════════════╝
"""


def _run_analysis(
    summary: dict,
    client_name: str,
    site: str,
    duration_str: str,
    output_dir: Path,
) -> None:
    from indus_probe.iec62443 import IEC62443Engine
    from indus_probe.report import generate_markdown_report, save_report

    assets       = summary["assets"]
    sessions     = summary["sessions"]
    proto_stats  = summary["protocol_stats"]
    observations = summary["observations"]
    total_pkts   = summary["total_packets"]

    print(f"\n📦 Assets discovered:   {len(assets)}")
    print(f"🔗 Sessions observed:   {len(sessions)}")
    print(f"📡 Protocols detected:  {list(proto_stats.keys())}")
    print(f"📝 Write operations:    {sum(1 for o in observations if o.get('is_write'))}")

    # IEC 62443 analysis
    print("\n🔍 Running IEC 62443 compliance analysis...")
    engine = IEC62443Engine()
    findings = engine.analyze(
        assets=assets,
        sessions=sessions,
        protocol_stats=proto_stats,
        raw_observations=observations,
    )
    sl_scores = engine.sl_score()

    print(f"📋 Findings generated: {len(findings)}")
    critical = sum(1 for f in findings if f.severity == "CRITICAL")
    high     = sum(1 for f in findings if f.severity == "HIGH")
    if critical:
        print(f"   🔴 CRITICAL: {critical}")
    if high:
        print(f"   🟠 HIGH:     {high}")

    # Generate report
    print("\n📄 Generating report...")
    report_md = generate_markdown_report(
        client_name=client_name,
        site_location=site,
        engagement_date=datetime.now().strftime("%Y-%m-%d"),
        capture_duration=duration_str,
        total_packets=total_pkts,
        assets=assets,
        sessions=sessions,
        protocol_stats=proto_stats,
        findings=findings,
        sl_scores=sl_scores,
    )

    out = save_report(
        report_md,
        output_dir=output_dir,
        base_name=f"IndusProbe_{client_name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}",
    )

    # OneAlert SOC Bridge export
    from indus_probe.onealert_bridge import export_to_onealert
    onealert_files = export_to_onealert(
        assets=assets,
        sessions=sessions,
        findings=findings,
        output_dir=output_dir,
    )

    print(f"\n✅ Assessment complete!")
    if out.get("pdf"):
        print(f"   Report (PDF):      {out['pdf']}")
    print(f"   Report (Markdown): {out['markdown']}")
    print(f"   OneAlert EVE Feed: {onealert_files['eve_jsonl']}")
    print(f"   OneAlert Assets:   {onealert_files['assets_json']}")


def cmd_pcap(args: argparse.Namespace) -> None:
    from indus_probe.capture import PcapAnalyzer

    print(BANNER)
    logger.info(f"Analysing PCAP: {args.file}")

    known = []
    if args.inventory:
        inv_path = Path(args.inventory)
        if inv_path.exists():
            known = inv_path.read_text().splitlines()
            logger.info(f"Loaded {len(known)} known assets from inventory")

    analyzer = PcapAnalyzer(known_assets=known)
    summary  = analyzer.analyze_pcap(args.file)

    _run_analysis(
        summary=summary,
        client_name=args.client,
        site=args.site,
        duration_str="PCAP file analysis",
        output_dir=Path(args.output),
    )


def cmd_live(args: argparse.Namespace) -> None:
    from indus_probe.capture import PcapAnalyzer

    print(BANNER)
    duration = args.duration
    hours    = duration // 3600
    minutes  = (duration % 3600) // 60

    logger.info(
        f"Starting PASSIVE live capture on '{args.interface}' for {hours}h {minutes}m. "
        f"NO packets will be transmitted."
    )
    print(f"\n⏱  Capture duration: {hours}h {minutes}m ({duration}s)")
    print(f"🌐 Interface: {args.interface}")
    print(f"🔇 Mode: PASSIVE ONLY — listen-only, zero transmission\n")

    known = []
    if args.inventory:
        inv_path = Path(args.inventory)
        if inv_path.exists():
            known = inv_path.read_text().splitlines()

    analyzer = PcapAnalyzer(known_assets=known)
    summary  = analyzer.analyze_live(interface=args.interface, duration_seconds=duration)

    _run_analysis(
        summary=summary,
        client_name=args.client,
        site=args.site,
        duration_str=f"{hours}h {minutes}m passive capture",
        output_dir=Path(args.output),
    )


def cmd_demo(args: argparse.Namespace) -> None:
    """Run a synthetic demo to verify the tool works end-to-end."""
    print(BANNER)
    print("🧪 Running DEMO mode with synthetic OT network data...\n")

    # Synthetic summary mimicking a real plant capture
    summary = {
        "total_packets": 125_430,
        "protocol_stats": {
            "Modbus TCP": 42_100,
            "S7Comm (Siemens)": 18_500,
            "EtherNet/IP / CIP (Rockwell)": 31_200,
            "OPC-UA": 14_300,
            "HART-IP (Yokogawa / Emerson)": 7_200,
            "DNP3": 5_800,
        },
        "assets": [
            {
                "ip": "192.168.10.11", "mac": "00:1B:1B:AA:BB:CC",
                "vendor": "Siemens", "device_hint": "S7 PLC / SIMATIC",
                "purdue_level": "Level 1", "protocols_seen": ["S7Comm (Siemens)"],
                "protocol_expected": ["S7Comm", "PROFINET"],
                "packet_count": 18500, "is_ot_device": True, "in_client_inventory": True,
            },
            {
                "ip": "192.168.10.21", "mac": "00:00:BC:11:22:33",
                "vendor": "Rockwell Automation", "device_hint": "ControlLogix PLC",
                "purdue_level": "Level 1", "protocols_seen": ["EtherNet/IP / CIP (Rockwell)"],
                "protocol_expected": ["EtherNet/IP", "CIP"],
                "packet_count": 31200, "is_ot_device": True, "in_client_inventory": True,
            },
            {
                "ip": "192.168.10.31", "mac": "00:80:F4:AA:BB:CC",
                "vendor": "Schneider Electric", "device_hint": "Modicon M340 PLC",
                "purdue_level": "Level 1", "protocols_seen": ["Modbus TCP"],
                "protocol_expected": ["Modbus TCP"],
                "packet_count": 42100, "is_ot_device": True, "in_client_inventory": True,
            },
            {
                "ip": "192.168.10.41", "mac": "00:0A:DC:55:66:77",
                "vendor": "Yokogawa", "device_hint": "CENTUM VP DCS / Field Gateway",
                "purdue_level": "Level 1", "protocols_seen": ["HART-IP (Yokogawa / Emerson)"],
                "protocol_expected": ["Vnet/IP", "HART"],
                "packet_count": 7200, "is_ot_device": True, "in_client_inventory": True,
            },
            {
                "ip": "192.168.10.50", "mac": "AA:BB:CC:DD:EE:FF",
                "vendor": "Unknown", "device_hint": "Unknown Device",
                "purdue_level": "Unknown", "protocols_seen": ["Modbus TCP"],
                "protocol_expected": [],
                "packet_count": 320, "is_ot_device": False, "in_client_inventory": False,
            },
            {
                "ip": "192.168.10.100", "mac": "00:50:56:AB:CD:EF",
                "vendor": "Unknown", "device_hint": "SCADA Server / HMI",
                "purdue_level": "Level 2-3", "protocols_seen": ["Modbus TCP", "EtherNet/IP / CIP (Rockwell)", "OPC-UA"],
                "protocol_expected": [],
                "packet_count": 8500, "is_ot_device": False, "in_client_inventory": True,
            },
        ],
        "sessions": [
            {"src_ip": "192.168.10.100", "dst_ip": "192.168.10.31", "src_port": 60123, "dst_port": 502,
             "protocol": "Modbus TCP", "packet_count": 4200, "byte_count": 210000, "is_write": True},
            {"src_ip": "192.168.10.100", "dst_ip": "192.168.10.11", "src_port": 49200, "dst_port": 102,
             "protocol": "S7Comm (Siemens)", "packet_count": 9100, "byte_count": 455000, "is_write": False},
            {"src_ip": "192.168.10.100", "dst_ip": "192.168.10.21", "src_port": 49300, "dst_port": 44818,
             "protocol": "EtherNet/IP / CIP (Rockwell)", "packet_count": 15600, "byte_count": 780000, "is_write": True},
            {"src_ip": "192.168.10.100", "dst_ip": "192.168.10.41", "src_port": 55094, "dst_port": 5094,
             "protocol": "HART-IP (Yokogawa / Emerson)", "packet_count": 7200, "byte_count": 360000, "is_write": True},
            {"src_ip": "192.168.10.100", "dst_ip": "192.168.10.100", "src_port": 54840, "dst_port": 4840,
             "protocol": "OPC-UA", "packet_count": 14300, "byte_count": 715000, "is_write": False},
            # Telnet — critical finding!
            {"src_ip": "192.168.1.50",  "dst_ip": "192.168.10.11", "src_port": 54321, "dst_port": 23,
             "protocol": "Unknown", "packet_count": 45, "byte_count": 1800, "is_write": False},
            # SMB — critical finding!
            {"src_ip": "192.168.1.60",  "dst_ip": "192.168.10.100", "src_port": 49400, "dst_port": 445,
             "protocol": "Unknown", "packet_count": 120, "byte_count": 48000, "is_write": False},
            # Cross-level (IT → OT)
            {"src_ip": "10.0.1.100",    "dst_ip": "192.168.10.31", "src_port": 60500, "dst_port": 502,
             "protocol": "Modbus TCP", "packet_count": 80, "byte_count": 3200, "is_write": True},
        ],
        "observations": [
            {"protocol": "Modbus TCP", "src_ip": "192.168.10.100", "dst_ip": "192.168.10.31",
             "is_write": True, "function_name": "Write Multiple Registers", "details": {"function_code": 16}},
            {"protocol": "EtherNet/IP / CIP (Rockwell)", "src_ip": "192.168.10.100", "dst_ip": "192.168.10.21",
             "is_write": True, "function_name": "Send Unit Data (Implicit I/O)", "details": {"command": 0x006F}},
            {"protocol": "HART-IP (Yokogawa / Emerson)", "src_ip": "192.168.10.100", "dst_ip": "192.168.10.41",
             "is_write": True, "function_name": "Write Polling Address", "details": {"hart_command": 6, "is_write": True}},
            {"protocol": "OPC-UA", "src_ip": "192.168.10.100", "dst_ip": "192.168.10.100",
             "is_write": False, "function_name": "OPC-UA OpenSecureChannel",
             "details": {"security_policy": "http://opcfoundation.org/UA/SecurityPolicy#None", "is_insecure": True}},
        ],
    }

    _run_analysis(
        summary=summary,
        client_name="DEMO — ABC Industrial Plant",
        site="Pune, Maharashtra, India",
        duration_str="48 hours (synthetic demo data)",
        output_dir=Path(args.output),
    )


def cmd_lab(args: argparse.Namespace) -> None:
    """Run an automated lab test on sample industrial PCAP."""
    from indus_probe.otforge_test import run_lab_test
    print(BANNER)
    pcap = args.pcap if hasattr(args, "pcap") and args.pcap else None
    res = run_lab_test(pcap)
    _run_analysis(
        summary=res["summary"],
        client_name="Testbed Lab Assessment",
        site="Virtual OT Environment (otforge / S7)",
        duration_str="Lab PCAP automated replay",
        output_dir=Path(args.output),
    )


def cmd_sensor(args: argparse.Namespace) -> None:
    """Run dedicated drop-box sensor daemon (Box PC / Raspberry Pi)."""
    from indus_probe.sensor import run_sensor
    print(BANNER)
    run_sensor(
        iface=args.interface,
        duration_hours=args.hours,
        client=args.client,
        site=args.site,
        output_dir=Path(args.output),
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="indus-probe",
        description="IndusProbe — OT Passive Scanner & IEC 62443 Reporter",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # --- pcap subcommand ---
    p_pcap = sub.add_parser("pcap", help="Analyse a saved PCAP/PCAPNG file")
    p_pcap.add_argument("--file",      required=True, help="Path to .pcap or .pcapng file")
    p_pcap.add_argument("--client",    default="Client",          help="Client company name")
    p_pcap.add_argument("--site",      default="Site Location",   help="Plant/site location")
    p_pcap.add_argument("--inventory", default="",               help="Text file with known IP addresses (one per line)")
    p_pcap.add_argument("--output",    default="./reports",       help="Output directory for reports")
    p_pcap.set_defaults(func=cmd_pcap)

    # --- live subcommand ---
    p_live = sub.add_parser("live", help="Passive live capture on a network interface")
    p_live.add_argument("--interface", required=True, help="Network interface (e.g. eth1, en0)")
    p_live.add_argument("--duration",  type=int, default=172800, help="Capture duration in seconds (default 48h)")
    p_live.add_argument("--client",    default="Client",        help="Client company name")
    p_live.add_argument("--site",      default="Site Location", help="Plant/site location")
    p_live.add_argument("--inventory", default="",             help="Text file with known IP addresses")
    p_live.add_argument("--output",    default="./reports",     help="Output directory for reports")
    p_live.set_defaults(func=cmd_live)

    # --- demo subcommand ---
    p_demo = sub.add_parser("demo", help="Run a demo with synthetic OT network data")
    p_demo.add_argument("--output", default="./reports", help="Output directory for reports")
    p_demo.set_defaults(func=cmd_demo)

    # --- lab subcommand ---
    p_lab = sub.add_parser("lab", help="Run automated test on a real sample OT PCAP (S7/DNP3)")
    p_lab.add_argument("--pcap", default=None, help="Optional PCAP path (defaults to S7 sample)")
    p_lab.add_argument("--output", default="./reports", help="Output directory for reports")
    p_lab.set_defaults(func=cmd_lab)

    # --- sensor subcommand (Drop-Box / RasPi) ---
    p_sensor = sub.add_parser("sensor", help="Run drop-box sensor daemon on portable Box PC or Raspberry Pi")
    p_sensor.add_argument("--interface", required=True, help="Network interface (e.g. eth1, enx...)")
    p_sensor.add_argument("--hours",     type=float, default=48.0, help="Duration in hours (default 48.0)")
    p_sensor.add_argument("--client",    default="Client Plant",   help="Client company name")
    p_sensor.add_argument("--site",      default="Site Location",  help="Plant/site location")
    p_sensor.add_argument("--output",    default="/opt/indusprobe", help="Output storage directory")
    p_sensor.set_defaults(func=cmd_sensor)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

