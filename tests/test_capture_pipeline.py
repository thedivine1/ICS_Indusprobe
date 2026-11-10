"""
Unit & Integration Tests for IndusProbe Capture Pipeline & Protocol Dissection
Validates:
- Transport payload extraction (no frame-tail slicing)
- Read-first / write-later session classification persistence
- Scapy fallback state reset (prevent duplicate state)
- Schneider Electric Modbus TCP and UMAS bounded decoding
- Rockwell Automation EtherNet/IP and CIP bounded decoding
- DEMO vs ASSESSMENT reporting modes and boundaries
"""

import os
import sys
from pathlib import Path

# Ensure review workspace takes absolute precedence over site-packages
REVIEW_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REVIEW_ROOT))

import struct
import tempfile
import unittest

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import wrpcap

from indus_probe.capture import PcapAnalyzer, Session, Asset
from indus_probe.protocols.detector import (
    Protocol, detect_protocol_from_payload, is_write_command,
    _parse_modbus, _parse_enip,
)
from indus_probe.report import generate_markdown_report


class TestCapturePipelineAndProtocols(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    # -----------------------------------------------------------------------
    # Priority 1: Capture Pipeline & State Invariants
    # -----------------------------------------------------------------------

    def test_session_read_first_write_later_persistence(self):
        """A session with an initial read followed by a write MUST remain marked as write."""
        analyzer = PcapAnalyzer()
        pcap_file = Path(self.temp_dir.name) / "read_then_write.pcap"

        # Packet 1: Modbus Read Holding Registers (FC 0x03)
        mbap_read = struct.pack(">HHHBB", 1, 0, 6, 1, 3) + b"\x00\x00\x00\x0a"
        pkt1 = Ether(src="00:80:f4:11:22:33", dst="00:80:f4:aa:bb:cc") / \
               IP(src="192.168.1.50", dst="192.168.1.10") / \
               TCP(sport=40001, dport=502) / Raw(load=mbap_read)

        # Packet 2: Modbus Write Single Register (FC 0x06)
        mbap_write = struct.pack(">HHHBB", 2, 0, 6, 1, 6) + b"\x00\x01\x12\x34"
        pkt2 = Ether(src="00:80:f4:11:22:33", dst="00:80:f4:aa:bb:cc") / \
               IP(src="192.168.1.50", dst="192.168.1.10") / \
               TCP(sport=40001, dport=502) / Raw(load=mbap_write)

        # Packet 3: Modbus Read Holding Registers (FC 0x03) again
        mbap_read2 = struct.pack(">HHHBB", 3, 0, 6, 1, 3) + b"\x00\x05\x00\x02"
        pkt3 = Ether(src="00:80:f4:11:22:33", dst="00:80:f4:aa:bb:cc") / \
               IP(src="192.168.1.50", dst="192.168.1.10") / \
               TCP(sport=40001, dport=502) / Raw(load=mbap_read2)

        wrpcap(str(pcap_file), [pkt1, pkt2, pkt3])

        summary = analyzer.analyze_pcap(pcap_file)
        self.assertEqual(summary["total_packets"], 3)
        self.assertEqual(len(summary["sessions"]), 1)

        sess = summary["sessions"][0]
        self.assertEqual(sess["src_ip"], "192.168.1.50")
        self.assertEqual(sess["dst_ip"], "192.168.1.10")
        self.assertEqual(sess["packet_count"], 3)
        self.assertEqual(sess["read_count"], 2)
        self.assertEqual(sess["write_count"], 1)
        self.assertTrue(sess["is_write"], "Session must be marked is_write=True even though packet 1 & 3 were reads")
        self.assertEqual(sess["classification"], "WRITE_OR_CONTROL")

    def test_undecoded_traffic_never_labeled_read_only(self):
        """Unsupported or undecoded operations must never be classified as read-only."""
        analyzer = PcapAnalyzer()
        pcap_file = Path(self.temp_dir.name) / "unsupported_fc.pcap"

        # Modbus packet with unsupported Function Code 99
        mbap_unknown = struct.pack(">HHHBB", 1, 0, 6, 1, 99) + b"\xde\xad\xbe\xef"
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=502) / Raw(load=mbap_unknown)
        wrpcap(str(pcap_file), [pkt])

        summary = analyzer.analyze_pcap(pcap_file)
        sess = summary["sessions"][0]
        self.assertEqual(sess["read_count"], 0)
        self.assertEqual(sess["write_count"], 0)
        self.assertEqual(sess["unsupported_count"], 1)
        self.assertEqual(sess["classification"], "UNSUPPORTED_OPERATION")
        self.assertFalse(sess["is_write"])

    def test_state_reset_on_fallback(self):
        """_reset_state() must completely clear accumulated state before re-running."""
        analyzer = PcapAnalyzer()
        # Seed state manually
        analyzer.assets["1.1.1.1"] = Asset(ip="1.1.1.1", mac="AA:BB:CC:DD:EE:FF", vendor_info=None)
        analyzer.sessions[("1.1.1.1", "2.2.2.2", "Modbus TCP", 502)] = Session(
            src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=502, protocol="Modbus TCP"
        )
        analyzer._packet_count = 50

        analyzer._reset_state()
        self.assertEqual(len(analyzer.assets), 0)
        self.assertEqual(len(analyzer.sessions), 0)
        self.assertEqual(analyzer._packet_count, 0)
        self.assertEqual(len(analyzer.protocol_stats), 0)

    # -----------------------------------------------------------------------
    # Priority 2: Schneider Electric & Modbus / UMAS Validation
    # -----------------------------------------------------------------------

    def test_schneider_modbus_standard_function_codes(self):
        """Validate standard Modbus FC classification."""
        # FC 0x01: Read Coils
        p_fc1 = struct.pack(">HHHBB", 1, 0, 6, 1, 1) + b"\x00\x00\x00\x10"
        res1 = _parse_modbus(p_fc1)
        self.assertIsNotNone(res1)
        self.assertEqual(res1["operation_type"], "READ")
        self.assertFalse(res1["is_write"])

        # FC 0x03: Read Holding Registers
        p_fc3 = struct.pack(">HHHBB", 2, 0, 6, 1, 3) + b"\x00\x00\x00\x08"
        res3 = _parse_modbus(p_fc3)
        self.assertIsNotNone(res3)
        self.assertEqual(res3["operation_type"], "READ")
        self.assertFalse(res3["is_write"])

        # FC 0x05: Write Single Coil
        p_fc5 = struct.pack(">HHHBB", 3, 0, 6, 1, 5) + b"\x00\x01\xff\x00"
        res5 = _parse_modbus(p_fc5)
        self.assertIsNotNone(res5)
        self.assertEqual(res5["operation_type"], "WRITE")
        self.assertTrue(res5["is_write"])

        # FC 0x10 (16): Write Multiple Registers
        p_fc16 = struct.pack(">HHHBB", 4, 0, 9, 1, 16) + b"\x00\x01\x00\x01\x02\x12\x34"
        res16 = _parse_modbus(p_fc16)
        self.assertIsNotNone(res16)
        self.assertEqual(res16["operation_type"], "WRITE")
        self.assertTrue(res16["is_write"])

    def test_schneider_modbus_device_id_fc43(self):
        """Validate FC 43 (0x2B) Read Device Identification response decoding."""
        # Build MEI response with Vendor Name "Schneider Electric" and Model "Modicon M340"
        vname = b"Schneider Electric"
        mname = b"BMX P34 2020"
        # MBAP (7B) + FC 43 (1B) + MEI 0x0E (1B) + DevID 0x01 + Conf 0x01 + More 0 + Next 0 + NumObjs 2
        header = struct.pack(">HHHBBBBBBBB", 1, 0, 10 + len(vname) + len(mname), 1, 43, 0x0E, 1, 1, 0, 0, 2)
        obj0 = struct.pack("BB", 0, len(vname)) + vname
        obj1 = struct.pack("BB", 1, len(mname)) + mname
        payload = header + obj0 + obj1

        res = _parse_modbus(payload)
        self.assertIsNotNone(res)
        self.assertEqual(res["operation_type"], "READ")
        self.assertEqual(res["observed_vendor"], "Schneider Electric")
        self.assertEqual(res["observed_model"], "BMX P34 2020")
        self.assertEqual(res["vendor_evidence"], "MODBUS_DEVICE_ID")

    def test_schneider_umas_bounded_decoding(self):
        """Validate bounded UMAS subcommands and safe fallback for unsupported codes."""
        # UMAS 0x01: Init Communication
        p_init = struct.pack(">HHHBB", 1, 0, 4, 1, 90) + b"\x01\x00"
        res_init = _parse_modbus(p_init)
        self.assertEqual(res_init["umas_code"], 0x01)
        self.assertEqual(res_init["operation_type"], "SESSION_MGMT")
        self.assertFalse(res_init["is_write"])
        self.assertEqual(res_init["observed_vendor"], "Schneider Electric")

        # UMAS 0x02: Read Memory Block / PLC Info
        p_read = struct.pack(">HHHBB", 2, 0, 4, 1, 90) + b"\x02\x00"
        res_read = _parse_modbus(p_read)
        self.assertEqual(res_read["umas_code"], 0x02)
        self.assertEqual(res_read["operation_type"], "READ")
        self.assertFalse(res_read["is_write"])

        # UMAS 0x04: Write Internal Bits (Write)
        p_write = struct.pack(">HHHBB", 3, 0, 6, 1, 90) + b"\x04\x00\x00\x01"
        res_write = _parse_modbus(p_write)
        self.assertEqual(res_write["umas_code"], 0x04)
        self.assertEqual(res_write["operation_type"], "WRITE")
        self.assertTrue(res_write["is_write"])

        # UMAS 0x50: Stop PLC (Write/Control)
        p_stop = struct.pack(">HHHBB", 4, 0, 4, 1, 90) + b"\x50\x00"
        res_stop = _parse_modbus(p_stop)
        self.assertEqual(res_stop["umas_code"], 0x50)
        self.assertEqual(res_stop["operation_type"], "WRITE")
        self.assertTrue(res_stop["is_write"])

        # UMAS 0x7E: Unsupported UMAS Subcommand
        p_unsupp = struct.pack(">HHHBB", 5, 0, 4, 1, 90) + b"\x7e\x00"
        res_unsupp = _parse_modbus(p_unsupp)
        self.assertEqual(res_unsupp["umas_code"], 0x7E)
        self.assertEqual(res_unsupp["operation_type"], "UNSUPPORTED")
        self.assertIsNone(res_unsupp["is_write"], "Unsupported UMAS operation must NOT be marked False (read-only)")

    # -----------------------------------------------------------------------
    # Priority 3: Rockwell Automation & EtherNet/IP / CIP Validation
    # -----------------------------------------------------------------------

    def test_rockwell_enip_encapsulation_commands(self):
        """Validate EtherNet/IP encapsulation commands without active clients."""
        # 0x0065: RegisterSession
        hdr_reg = struct.pack("<HHII8sI", 0x0065, 4, 0x12345678, 0, b"\x00" * 8, 0) + b"\x01\x00\x00\x00"
        res_reg = _parse_enip(hdr_reg)
        self.assertIsNotNone(res_reg)
        self.assertEqual(res_reg["command"], 0x0065)
        self.assertEqual(res_reg["operation_type"], "SESSION_MGMT")
        self.assertFalse(res_reg["is_write"])

        # 0x0004: ListServices
        hdr_ls = struct.pack("<HHII8sI", 0x0004, 0, 0, 0, b"\x00" * 8, 0)
        res_ls = _parse_enip(hdr_ls)
        self.assertIsNotNone(res_ls)
        self.assertEqual(res_ls["command"], 0x0004)
        self.assertEqual(res_ls["operation_type"], "SESSION_MGMT")

    def test_rockwell_list_identity_response(self):
        """Validate CIP ListIdentity response extracting Rockwell Automation identity."""
        pname = b"1756-L83E ControlLogix"
        # Encap Header: Cmd=0x0063 (ListIdentity), Len=63+len(pname), Sess=0, Status=0
        encap_len = 39 + len(pname)
        encap = struct.pack("<HHII8sI", 0x0063, encap_len, 0, 0, b"\x00" * 8, 0)

        # CPF: Item count = 1
        cpf_header = struct.pack("<H", 1)
        # Item: Type = 0x000C (Identity Item), Length = 35 + len(pname)
        item_len = 35 + len(pname)
        item_header = struct.pack("<HH", 0x000C, item_len)

        # Identity item data:
        # Encapsulation version(2) + Socket address(16)
        # Vendor ID(2, uint16=1 -> Rockwell)
        # Device Type(2, uint16=0x000E -> PLC)
        # Product Code(2, uint16=0x00A1)
        # Revision: Major(1)=32, Minor(1)=11
        # Status(2)=0x0060
        # Serial(4)=0x12345678
        # Name len(1) + Name string
        item_data = b"\x01\x00" + (b"\x00" * 16) + \
                    struct.pack("<HHHBBHI", 1, 0x000E, 0x00A1, 32, 11, 0x0060, 0x12345678) + \
                    struct.pack("B", len(pname)) + pname

        payload = encap + cpf_header + item_header + item_data
        res = _parse_enip(payload)

        self.assertIsNotNone(res)
        self.assertEqual(res["observed_vendor"], "Rockwell Automation")
        self.assertEqual(res["observed_model"], "1756-L83E ControlLogix")
        self.assertEqual(res["observed_firmware"], "v32.11")
        self.assertEqual(res["vendor_evidence"], "CIP_IDENTITY")
        self.assertEqual(res["operation_type"], "READ")

    def test_rockwell_cip_operation_decoding_in_sendrrdata(self):
        """Distinguish CIP Read Tag (0x4C) vs Write Tag (0x4D) inside SendRRData encapsulation."""
        # 1. CIP Read Tag Service (0x4C)
        cip_read_data = b"\x4c\x02\x20\x6b\x24\x01\x01\x00"  # Read Tag request
        # SendRRData (0x006F): Encap Header (24B) + Interface Handle(4B)=0 + Timeout(2B)=0
        # CPF: Item count = 2 -> Null Address Item (Type 0x0000, Len 0), Data Item (Type 0x00B2, Len)
        cpf_items = struct.pack("<HH", 0x0000, 0) + struct.pack("<HH", 0x00B2, len(cip_read_data)) + cip_read_data
        cpf = struct.pack("<H", 2) + cpf_items
        encap_read = struct.pack("<HHII8sI", 0x006F, 6 + len(cpf), 0x11223344, 0, b"\x00" * 8, 0) + \
                     b"\x00\x00\x00\x00\x00\x00" + cpf

        res_read = _parse_enip(encap_read)
        self.assertIsNotNone(res_read)
        self.assertTrue(res_read["cip_decoded"])
        self.assertEqual(res_read["cip_service_code"], 0x4C)
        self.assertEqual(res_read["operation_type"], "READ")
        self.assertFalse(res_read["is_write"])

        # 2. CIP Write Tag Service (0x4D)
        cip_write_data = b"\x4d\x02\x20\x6b\x24\x01\xc4\x00\x01\x00\x12\x34"
        cpf_write_items = struct.pack("<HH", 0x0000, 0) + struct.pack("<HH", 0x00B2, len(cip_write_data)) + cip_write_data
        cpf_w = struct.pack("<H", 2) + cpf_write_items
        encap_write = struct.pack("<HHII8sI", 0x006F, 6 + len(cpf_w), 0x11223344, 0, b"\x00" * 8, 0) + \
                      b"\x00\x00\x00\x00\x00\x00" + cpf_w

        res_write = _parse_enip(encap_write)
        self.assertIsNotNone(res_write)
        self.assertTrue(res_write["cip_decoded"])
        self.assertEqual(res_write["cip_service_code"], 0x4D)
        self.assertEqual(res_write["operation_type"], "WRITE")
        self.assertTrue(res_write["is_write"])

        # 3. Unsupported CIP Service (0x3B)
        cip_unsupp_data = b"\x3b\x02\x20\x6b\x24\x01"
        cpf_u_items = struct.pack("<HH", 0x0000, 0) + struct.pack("<HH", 0x00B2, len(cip_unsupp_data)) + cip_unsupp_data
        cpf_u = struct.pack("<H", 2) + cpf_u_items
        encap_unsupp = struct.pack("<HHII8sI", 0x006F, 6 + len(cpf_u), 0x11223344, 0, b"\x00" * 8, 0) + \
                       b"\x00\x00\x00\x00\x00\x00" + cpf_u

        res_unsupp = _parse_enip(encap_unsupp)
        self.assertIsNotNone(res_unsupp)
        self.assertTrue(res_unsupp["cip_decoded"])
        self.assertEqual(res_unsupp["cip_service_code"], 0x3B)
        self.assertEqual(res_unsupp["operation_type"], "UNSUPPORTED")
        self.assertIsNone(res_unsupp["is_write"], "Unsupported CIP service must NOT be marked False (read-only)")

    # -----------------------------------------------------------------------
    # Priority 4: Report Boundaries (ASSESSMENT vs DEMO)
    # -----------------------------------------------------------------------

    def test_assessment_mode_omits_synthetic_disclaimers_and_disables_advisories(self):
        """ASSESSMENT mode must produce professional audit output with dormant advisories."""
        assets = [
            {
                "ip": "192.168.1.10",
                "mac": "00:00:BC:11:22:33",
                "vendor": "Rockwell Automation",
                "observed_vendor": "Rockwell Automation",
                "observed_model": "1756-L83E ControlLogix",
                "identity_evidence": "CIP_IDENTITY",
                "confidence": "HIGH",
                "device_hint": "ControlLogix PLC",
                "purdue_level": "Level 1",
                "protocols_seen": ["EtherNet/IP / CIP (Rockwell)"],
                "packet_count": 120,
                "is_ot_device": True,
                "in_client_inventory": True,
            }
        ]
        sessions = [
            {
                "src_ip": "192.168.1.50",
                "dst_ip": "192.168.1.10",
                "src_port": 50000,
                "dst_port": 44818,
                "protocol": "EtherNet/IP / CIP (Rockwell)",
                "packet_count": 120,
                "read_count": 100,
                "write_count": 20,
                "undecoded_count": 0,
                "unsupported_count": 0,
                "is_write": True,
                "classification": "WRITE_OR_CONTROL",
            }
        ]
        protocol_stats = {"EtherNet/IP / CIP (Rockwell)": 120}

        report_md = generate_markdown_report(
            client_name="Acme Power Plant",
            site_location="Turbine Unit 1",
            engagement_date="2026-11-11",
            capture_duration="2 hours",
            total_packets=120,
            assets=assets,
            sessions=sessions,
            protocol_stats=protocol_stats,
            findings=[],
            sl_scores={},
            mode="ASSESSMENT",
        )

        # Invariants:
        self.assertNotIn("DEMONSTRATION REPORT — SYNTHETIC / LAB-GENERATED TRAFFIC", report_md)
        self.assertNotIn("Fictional cement manufacturing environment", report_md)
        self.assertIn("Industrial OT Network Passive Visibility & Telemetry Assessment", report_md)
        self.assertIn("AUTOMATED ADVISORY EVALUATION NOT ENABLED", report_md)
        self.assertIn("WRITE_OR_CONTROL", report_md)
        self.assertIn("CIP_IDENTITY", report_md)
        self.assertIn("Rockwell Automation", report_md)


if __name__ == "__main__":
    unittest.main()
