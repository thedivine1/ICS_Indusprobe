"""
IndusProbe — Field Drop-Box Sensor Daemon

Runs on a portable Box PC or Raspberry Pi 4/5.
Controls the network interface in 100% listen-only stealth mode, manages disk-safe
ring buffers, and automatically compiles the IEC 62443 audit package when the timer completes.
"""

from __future__ import annotations
import argparse
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path


def configure_stealth_interface(iface: str) -> bool:
    """
    Enforces OS-level listen-only silence on Linux:
    - Drops any assigned IP
    - Disables ARP and IPv6 auto-configuration
    - Sets promiscuous mode
    """
    if sys.platform != "linux":
        print(f"⚠️  Note: Stealth kernel tuning is designed for Linux (Raspberry Pi / Box PC).")
        return True

    commands = [
        ["ip", "link", "set", iface, "down"],
        ["sysctl", "-w", f"net.ipv6.conf.{iface}.disable_ipv6=1"],
        ["sysctl", "-w", f"net.ipv6.conf.{iface}.autoconf=0"],
        ["sysctl", "-w", f"net.ipv6.conf.{iface}.accept_ra=0"],
        ["sysctl", "-w", f"net.ipv4.conf.{iface}.arp_ignore=8"],
        ["sysctl", "-w", f"net.ipv4.conf.{iface}.arp_announce=2"],
        ["ip", "addr", "flush", "dev", iface],
        ["ip", "link", "set", iface, "promisc", "on", "arp", "off", "up"],
    ]

    for cmd in commands:
        try:
            subprocess.run(["sudo"] + cmd, check=True, capture_output=True)
        except Exception as e:
            print(f"⚠️  Warning running {' '.join(cmd)}: {e}")
            return False

    print(f"🛡️  Interface '{iface}' configured in 100% STEALTH LISTEN-ONLY mode.")
    return True


def run_sensor(
    iface: str,
    duration_hours: float,
    client: str,
    site: str,
    output_dir: Path,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    pcap_dir = output_dir / "pcaps"
    reports_dir = output_dir / "reports"
    pcap_dir.mkdir(exist_ok=True)
    reports_dir.mkdir(exist_ok=True)

    print("\n" + "=" * 60)
    print("  IndusProbe Field Drop-Box Sensor")
    print(f"  Target Interface : {iface}")
    print(f"  Duration         : {duration_hours} hours")
    print(f"  Client           : {client} ({site})")
    print(f"  Output Folder    : {output_dir}")
    print("=" * 60 + "\n")

    configure_stealth_interface(iface)

    duration_secs = int(duration_hours * 3600)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_pcap = pcap_dir / f"sensor_capture_{ts}.pcap"

    print(f"\n📡 Starting passive capture: {target_pcap.name}")
    print(f"⏳ Capture ends at: {(datetime.now() + timedelta(seconds=duration_secs)).strftime('%Y-%m-%d %H:%M:%S')}")
    print("💡 You may now leave the drop-box unattended in the plant cabinet.\n")

    # Prefer dumpcap, fallback to tcpdump, fallback to scapy
    capture_tool = None
    if shutil.which("dumpcap"):
        capture_tool = "dumpcap"
        cmd = [
            "sudo", "dumpcap", "-i", iface,
            "-a", f"duration:{duration_secs}",
            "-b", "filesize:500000",  # 500 MB segments
            "-b", "files:40",        # max 20 GB ring buffer
            "-w", str(target_pcap),
            "-q",
        ]
    elif shutil.which("tcpdump"):
        capture_tool = "tcpdump"
        cmd = [
            "sudo", "tcpdump", "-i", iface,
            "-s", "0", "-n", "-p",
            "-G", str(duration_secs),
            "-W", "1",
            "-w", str(target_pcap),
        ]
    else:
        capture_tool = "indus-internal"
        cmd = None

    if cmd:
        try:
            subprocess.run(cmd, check=True)
        except KeyboardInterrupt:
            print("\n⏹️  Capture stopped manually by user.")
    else:
        # Internal python capture fallback
        from indus_probe.capture import PcapAnalyzer
        analyzer = PcapAnalyzer()
        summary = analyzer.analyze_live(iface, duration_secs)
        # Process and exit
        from indus_probe.cli import _run_analysis
        _run_analysis(summary, client, site, f"{duration_hours}h field sensor", reports_dir)
        return

    # Post-capture processing for dumpcap / tcpdump
    pcap_files = sorted(pcap_dir.glob(f"sensor_capture_{ts}*.pcap"), key=os.path.getmtime)
    if not pcap_files:
        print("⚠️  No pcap files recorded.")
        return

    latest_pcap = pcap_files[-1]
    print(f"\n📦 Processing completed capture: {latest_pcap.name} ({latest_pcap.stat().st_size / (1024*1024):.1f} MB)")
    
    from indus_probe.capture import PcapAnalyzer
    from indus_probe.cli import _run_analysis
    analyzer = PcapAnalyzer()
    summary = analyzer.analyze_pcap(latest_pcap)
    _run_analysis(summary, client, site, f"{duration_hours}h field sensor", reports_dir)
    print("\n🎉 Drop-box assessment completed successfully!")

