"""
Generate End-to-End Pilot Demonstration Reports for Schneider Electric and Rockwell Automation

Demonstrates:
- Scoped passive capture analysis
- Exact packet, session, and operation counting
- Separation of physical identity evidence (CIP ListIdentity, Modbus Device ID) from OUI inference
- Bounded UMAS & CIP decoding with unknown/unsupported handling
- DEMO mode with synthetic/lab-generated data disclaimer

IMPORTANT: These reports are generated from SYNTHETIC PCAP fixtures constructed
in memory and are labelled DEMONSTRATION REPORT to prevent confusion with real
operational assessments.  ASSESSMENT mode must only be used with actual capture
data from real site deployments.
"""

import os
import sys
from pathlib import Path

# Ensure local review workspace is prioritized
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import struct
import tempfile
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import wrpcap

from indus_probe.capture import PcapAnalyzer
from indus_probe.iec62443 import IEC62443Engine
from indus_probe.report import generate_markdown_report


def build_schneider_pcap(path: Path) -> None:
    """Build a protocol-conformant Schneider Electric Modbus TCP & UMAS PCAP."""
    pkts = []
    src_hmi = "192.168.10.100"
    mac_hmi = "00:50:56:FE:DC:BA"  # VMware / Supervisory HMI

    src_eng = "192.168.10.50"
    mac_eng = "00:50:56:A1:B2:C3"  # Engineering Workstation

    dst_plc = "192.168.10.31"
    mac_plc = "00:80:F4:12:34:56"  # Schneider Electric OUI (Modicon M340)

    dst_vfd = "192.168.10.32"
    mac_vfd = "98:F4:AB:55:66:77"  # Schneider Electric OUI (Altivar VFD)

    # 1. Modbus FC 43 (Read Device Identification) Response from M340 PLC
    vname = b"Schneider Electric"
    mname = b"BMX P34 2020"
    rev = b"v03.20"
    # MBAP length = 8 fixed (UID+FC+MEI+RDevID+Conf+More+Next+NumObjs) + obj lengths
    mbap_len = 8 + 2 + len(vname) + 2 + len(mname) + 2 + len(rev)
    hdr43 = struct.pack(">HHHBBBBBBBB", 101, 0, mbap_len, 1, 43, 0x0E, 1, 1, 0, 0, 3)
    obj0 = struct.pack("BB", 0, len(vname)) + vname
    obj1 = struct.pack("BB", 1, len(mname)) + mname
    obj2 = struct.pack("BB", 2, len(rev)) + rev
    pkt_id = Ether(src=mac_plc, dst=mac_eng) / IP(src=dst_plc, dst=src_eng) / TCP(sport=502, dport=49152) / Raw(load=hdr43 + obj0 + obj1 + obj2)
    pkts.append(pkt_id)

    # 2. HMI Polling M340 PLC: Modbus FC 0x03 (Read Holding Registers) - 50 packets
    for i in range(1, 51):
        req = struct.pack(">HHHBB", i, 0, 6, 1, 3) + b"\x00\x00\x00\x0a"
        pkts.append(Ether(src=mac_hmi, dst=mac_plc) / IP(src=src_hmi, dst=dst_plc) / TCP(sport=50001, dport=502) / Raw(load=req))

    # 3. HMI Setpoint Command to M340: Modbus FC 0x10 (Write Multiple Registers) - 5 packets
    for i in range(51, 56):
        w_req = struct.pack(">HHHBB", i, 0, 11, 1, 16) + b"\x00\x10\x00\x02\x04\x01\x02\x03\x04"
        pkts.append(Ether(src=mac_hmi, dst=mac_plc) / IP(src=src_hmi, dst=dst_plc) / TCP(sport=50001, dport=502) / Raw(load=w_req))

    # 4. HMI Control of Altivar VFD: Modbus FC 0x06 (Write Single Register) - 10 packets
    for i in range(60, 70):
        vfd_w = struct.pack(">HHHBB", i, 0, 6, 1, 6) + b"\x20\x01\x05\xDC"
        pkts.append(Ether(src=mac_hmi, dst=mac_vfd) / IP(src=src_hmi, dst=dst_vfd) / TCP(sport=50002, dport=502) / Raw(load=vfd_w))

    # 5. Engineering Workstation UMAS Maintenance Session to M340:
    # - UMAS 0x01: Init Communication (1 pkt)
    pkts.append(Ether(src=mac_eng, dst=mac_plc) / IP(src=src_eng, dst=dst_plc) / TCP(sport=50005, dport=502) / Raw(load=struct.pack(">HHHBB", 201, 0, 4, 1, 90) + b"\x01\x00"))
    # - UMAS 0x02: Read Memory Block (10 pkts)
    for i in range(202, 212):
        pkts.append(Ether(src=mac_eng, dst=mac_plc) / IP(src=src_eng, dst=dst_plc) / TCP(sport=50005, dport=502) / Raw(load=struct.pack(">HHHBB", i, 0, 4, 1, 90) + b"\x02\x00"))
    # - UMAS 0x04: Write Internal Bits (3 pkts)
    for i in range(212, 215):
        pkts.append(Ether(src=mac_eng, dst=mac_plc) / IP(src=src_eng, dst=dst_plc) / TCP(sport=50005, dport=502) / Raw(load=struct.pack(">HHHBB", i, 0, 6, 1, 90) + b"\x04\x00\x00\x01"))
    # - UMAS 0x30: Read Executive ID (1 pkt)
    pkts.append(Ether(src=mac_eng, dst=mac_plc) / IP(src=src_eng, dst=dst_plc) / TCP(sport=50005, dport=502) / Raw(load=struct.pack(">HHHBB", 215, 0, 4, 1, 90) + b"\x30\x00"))
    # - UMAS 0x50: Stop PLC (1 pkt) - High-risk write/control command
    pkts.append(Ether(src=mac_eng, dst=mac_plc) / IP(src=src_eng, dst=dst_plc) / TCP(sport=50005, dport=502) / Raw(load=struct.pack(">HHHBB", 216, 0, 4, 1, 90) + b"\x50\x00"))
    # - UMAS 0x7E: Unsupported UMAS Subcommand (1 pkt) - classified as unsupported, not read-only
    pkts.append(Ether(src=mac_eng, dst=mac_plc) / IP(src=src_eng, dst=dst_plc) / TCP(sport=50005, dport=502) / Raw(load=struct.pack(">HHHBB", 217, 0, 4, 1, 90) + b"\x7e\x00"))

    wrpcap(str(path), pkts)


def build_rockwell_pcap(path: Path) -> None:
    """Build a protocol-conformant Rockwell Automation EtherNet/IP & CIP PCAP."""
    pkts = []
    src_scada = "192.168.20.100"
    mac_scada = "00:50:56:FE:DC:BA"  # VMware / Supervisory SCADA

    dst_plc = "192.168.20.21"
    mac_plc = "00:00:BC:88:99:AA"  # Rockwell Automation OUI (ControlLogix)

    dst_drive = "192.168.20.22"
    mac_drive = "00:08:28:33:44:55"  # Rockwell Automation OUI (PowerFlex)

    # 1. EtherNet/IP Command 0x0065: RegisterSession
    reg_req = struct.pack("<HHII8sI", 0x0065, 4, 0, 0, b"\x00" * 8, 0) + b"\x01\x00\x00\x00"
    pkts.append(Ether(src=mac_scada, dst=mac_plc) / IP(src=src_scada, dst=dst_plc) / TCP(sport=49300, dport=44818) / Raw(load=reg_req))

    session_handle = 0x00123456

    # 2. EtherNet/IP Command 0x0063: ListIdentity Response from ControlLogix PLC
    pname = b"1756-L83E ControlLogix"
    encap_len = 39 + len(pname)
    encap = struct.pack("<HHII8sI", 0x0063, encap_len, session_handle, 0, b"\x00" * 8, 0)
    cpf_header = struct.pack("<H", 1)
    item_len = 35 + len(pname)
    item_header = struct.pack("<HH", 0x000C, item_len)
    item_data = b"\x01\x00" + (b"\x00" * 16) + \
                struct.pack("<HHHBBHI", 1, 0x000E, 0x00A1, 33, 11, 0x0060, 0x99887766) + \
                struct.pack("B", len(pname)) + pname
    pkts.append(Ether(src=mac_plc, dst=mac_scada) / IP(src=dst_plc, dst=src_scada) / TCP(sport=44818, dport=49300) / Raw(load=encap + cpf_header + item_header + item_data))

    # 3. CIP Read Tag Service (0x4C) via SendRRData (0x006F) - 40 packets
    cip_read = b"\x4c\x02\x20\x6b\x24\x01\x01\x00"
    cpf_read = struct.pack("<H", 2) + struct.pack("<HH", 0x0000, 0) + struct.pack("<HH", 0x00B2, len(cip_read)) + cip_read
    send_rr_read = struct.pack("<HHII8sI", 0x006F, 6 + len(cpf_read), session_handle, 0, b"\x00" * 8, 0) + b"\x00\x00\x00\x00\x00\x00" + cpf_read
    for _ in range(40):
        pkts.append(Ether(src=mac_scada, dst=mac_plc) / IP(src=src_scada, dst=dst_plc) / TCP(sport=49300, dport=44818) / Raw(load=send_rr_read))

    # 4. CIP Write Tag Service (0x4D) via SendRRData (0x006F) - 8 packets
    cip_write = b"\x4d\x02\x20\x6b\x24\x01\xc4\x00\x01\x00\x12\x34"
    cpf_write = struct.pack("<H", 2) + struct.pack("<HH", 0x0000, 0) + struct.pack("<HH", 0x00B2, len(cip_write)) + cip_write
    send_rr_write = struct.pack("<HHII8sI", 0x006F, 6 + len(cpf_write), session_handle, 0, b"\x00" * 8, 0) + b"\x00\x00\x00\x00\x00\x00" + cpf_write
    for _ in range(8):
        pkts.append(Ether(src=mac_scada, dst=mac_plc) / IP(src=src_scada, dst=dst_plc) / TCP(sport=49300, dport=44818) / Raw(load=send_rr_write))

    # 5. CIP Get Attribute Single (0x0E) - 15 packets
    cip_gas = b"\x0e\x02\x20\x01\x24\x01"
    cpf_gas = struct.pack("<H", 2) + struct.pack("<HH", 0x0000, 0) + struct.pack("<HH", 0x00B2, len(cip_gas)) + cip_gas
    send_rr_gas = struct.pack("<HHII8sI", 0x006F, 6 + len(cpf_gas), session_handle, 0, b"\x00" * 8, 0) + b"\x00\x00\x00\x00\x00\x00" + cpf_gas
    for _ in range(15):
        pkts.append(Ether(src=mac_scada, dst=mac_drive) / IP(src=src_scada, dst=dst_drive) / TCP(sport=49301, dport=44818) / Raw(load=send_rr_gas))

    # 6. CIP Set Attributes All (0x02) - 2 packets (Write)
    cip_saa = b"\x02\x02\x20\x01\x24\x01\xaa\xbb"
    cpf_saa = struct.pack("<H", 2) + struct.pack("<HH", 0x0000, 0) + struct.pack("<HH", 0x00B2, len(cip_saa)) + cip_saa
    send_rr_saa = struct.pack("<HHII8sI", 0x006F, 6 + len(cpf_saa), session_handle, 0, b"\x00" * 8, 0) + b"\x00\x00\x00\x00\x00\x00" + cpf_saa
    for _ in range(2):
        pkts.append(Ether(src=mac_scada, dst=mac_drive) / IP(src=src_scada, dst=dst_drive) / TCP(sport=49301, dport=44818) / Raw(load=send_rr_saa))

    # 7. Unsupported CIP service 0x3B - 1 packet (classified as unsupported, not read-only)
    cip_unsupp = b"\x3b\x02\x20\x01\x24\x01"
    cpf_unsupp = struct.pack("<H", 2) + struct.pack("<HH", 0x0000, 0) + struct.pack("<HH", 0x00B2, len(cip_unsupp)) + cip_unsupp
    send_rr_unsupp = struct.pack("<HHII8sI", 0x006F, 6 + len(cpf_unsupp), session_handle, 0, b"\x00" * 8, 0) + b"\x00\x00\x00\x00\x00\x00" + cpf_unsupp
    pkts.append(Ether(src=mac_scada, dst=mac_plc) / IP(src=src_scada, dst=dst_plc) / TCP(sport=49300, dport=44818) / Raw(load=send_rr_unsupp))

    wrpcap(str(path), pkts)


def main():
    sample_reports_dir = ROOT_DIR / "sample_reports"
    sample_reports_dir.mkdir(exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        # -------------------------------------------------------------------
        # Schneider Electric Pilot Assessment Generation
        # -------------------------------------------------------------------
        print("🔧 Generating Schneider Electric Pilot PCAP & Report...")
        schneider_pcap = tmp_path / "schneider_pilot.pcap"
        build_schneider_pcap(schneider_pcap)

        analyzer_s = PcapAnalyzer()
        summary_s = analyzer_s.analyze_pcap(schneider_pcap)

        engine_s = IEC62443Engine()
        findings_s = engine_s.analyze(
            assets=summary_s["assets"],
            sessions=summary_s["sessions"],
            protocol_stats=summary_s["protocol_stats"],
            raw_observations=summary_s["observations"],
        )
        sl_scores_s = engine_s.sl_score()

        report_schneider_md = generate_markdown_report(
            client_name="Schneider Electric Pilot Installation",
            site_location="Manufacturing Cell 3 — Modicon Line",
            engagement_date="2026-11-11",
            capture_duration="Passive Mirror Session (82 frames)",
            total_packets=summary_s["total_packets"],
            assets=summary_s["assets"],
            sessions=summary_s["sessions"],
            protocol_stats=summary_s["protocol_stats"],
            findings=findings_s,
            sl_scores=sl_scores_s,
            consultant_name="IndusProbe v1.1 Passive Engine",
            report_version="v1.1-pilot-demo-schneider",
            mode="DEMO",
            is_synthetic=True,
        )

        out_s = sample_reports_dir / "schneider_pilot_demo_example.md"
        out_s.write_text(report_schneider_md, encoding="utf-8")
        print(f"✅ Schneider Pilot Demo Report written to: {out_s}")

        # -------------------------------------------------------------------
        # Rockwell Automation Pilot Assessment Generation
        # -------------------------------------------------------------------
        print("🔧 Generating Rockwell Automation Pilot PCAP & Report...")
        rockwell_pcap = tmp_path / "rockwell_pilot.pcap"
        build_rockwell_pcap(rockwell_pcap)

        analyzer_r = PcapAnalyzer()
        summary_r = analyzer_r.analyze_pcap(rockwell_pcap)

        engine_r = IEC62443Engine()
        findings_r = engine_r.analyze(
            assets=summary_r["assets"],
            sessions=summary_r["sessions"],
            protocol_stats=summary_r["protocol_stats"],
            raw_observations=summary_r["observations"],
        )
        sl_scores_r = engine_r.sl_score()

        report_rockwell_md = generate_markdown_report(
            client_name="Rockwell Automation Pilot Installation",
            site_location="Packaging Facility — Line 1 ControlLogix",
            engagement_date="2026-11-11",
            capture_duration="Passive Mirror Session (68 frames)",
            total_packets=summary_r["total_packets"],
            assets=summary_r["assets"],
            sessions=summary_r["sessions"],
            protocol_stats=summary_r["protocol_stats"],
            findings=findings_r,
            sl_scores=sl_scores_r,
            consultant_name="IndusProbe v1.1 Passive Engine",
            report_version="v1.1-pilot-demo-rockwell",
            mode="DEMO",
            is_synthetic=True,
        )

        out_r = sample_reports_dir / "rockwell_pilot_demo_example.md"
        out_r.write_text(report_rockwell_md, encoding="utf-8")
        print(f"✅ Rockwell Pilot Demo Report written to: {out_r}")


if __name__ == "__main__":
    main()

