"""
IndusProbe — Lab & PCAP Test Runner

Automated validation runner using real industrial PCAP captures from the
testbed suite (e.g. S7Comm, DNP3, Modbus, OpenPLC).
"""

from __future__ import annotations
import sys
from pathlib import Path
from indus_probe.capture import PcapAnalyzer
from indus_probe.iec62443 import IEC62443Engine


def run_lab_test(pcap_path: str | Path | None = None) -> dict:
    """
    Run automated test against a sample industrial PCAP.
    If none provided, defaults to industrial-scanner S7 PCAPs.
    """
    if pcap_path is None:
        default_pcap = Path("/Users/tejas/Documents/chaitanya/ICS/industrial-scanner/pcaps/s7/step7_s300_stop.pcapng")
        if not default_pcap.exists():
            default_pcap = Path("/Users/tejas/Documents/chaitanya/ICS/industrial-scanner/pcaps/dnp3/read_and_response.pcap")
        pcap_path = default_pcap

    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(f"Test PCAP not found: {path}")

    print(f"\n🔬 Running IndusProbe Lab Test on: {path.name}")
    analyzer = PcapAnalyzer()
    summary = analyzer.analyze_pcap(path)

    engine = IEC62443Engine()
    findings = engine.analyze(
        assets=summary["assets"],
        sessions=summary["sessions"],
        protocol_stats=summary["protocol_stats"],
        raw_observations=summary["observations"],
    )

    print(f"   Packets parsed:      {summary['total_packets']}")
    print(f"   Assets identified:   {len(summary['assets'])}")
    print(f"   Protocols:           {list(summary['protocol_stats'].keys())}")
    print(f"   IEC 62443 Findings:  {len(findings)}")

    return {
        "summary": summary,
        "findings": findings,
    }


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    run_lab_test(target)

