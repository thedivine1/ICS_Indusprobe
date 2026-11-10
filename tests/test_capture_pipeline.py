"""
Unit & Integration Tests for IndusProbe Capture Pipeline & Protocol Dissection
Validates:
- Transport payload extraction (no frame-tail slicing)
- Read-first / write-later session classification persistence
- Scapy fallback state reset (prevent duplicate state)
- Schneider Electric Modbus TCP and UMAS bounded decoding
- Rockwell Automation EtherNet/IP and CIP bounded decoding
- DEMO vs ASSESSMENT reporting modes and boundaries
- Identity ownership (identity applied only to the responding / addressed endpoint)
- Session key includes src_port (no collision between different ephemeral ports)
- SESSION_MGMT frames not counted as reads
- Mixed read/unknown classification
- Modbus length validation (truncated / multi-PDU)
- CIP connected vs unconnected framing (SendUnitData Connection Sequence Number skip)
- CIP write confirmation requires response status 0x00
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
        analyzer.sessions[("1.1.1.1", 1000, "2.2.2.2", 502, "Modbus TCP")] = Session(
            src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=502, protocol="Modbus TCP"
        )
        analyzer._packet_count = 50

        analyzer._reset_state()
        self.assertEqual(len(analyzer.assets), 0)
        self.assertEqual(len(analyzer.sessions), 0)
        self.assertEqual(analyzer._packet_count, 0)
        self.assertEqual(len(analyzer.protocol_stats), 0)

    # -----------------------------------------------------------------------
    # Priority 1b: Session Key & Classification Correctness
    # -----------------------------------------------------------------------

    def test_session_key_includes_src_port(self):
        """Two connections from different src ports to the same dst/port must produce 2 sessions."""
        analyzer = PcapAnalyzer()
        pcap_file = Path(self.temp_dir.name) / "two_src_ports.pcap"

        mbap = struct.pack(">HHHBB", 1, 0, 6, 1, 3) + b"\x00\x00\x00\x0a"
        pkt1 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / \
               TCP(sport=40001, dport=502) / Raw(load=mbap)
        pkt2 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / \
               TCP(sport=40002, dport=502) / Raw(load=mbap)
        wrpcap(str(pcap_file), [pkt1, pkt2])

        summary = analyzer.analyze_pcap(pcap_file)
        self.assertEqual(len(summary["sessions"]), 2,
                         "Different ephemeral source ports must produce distinct sessions")

    def test_session_mgmt_not_counted_as_read(self):
        """EtherNet/IP RegisterSession (SESSION_MGMT) must not increment read_count."""
        analyzer = PcapAnalyzer()
        pcap_file = Path(self.temp_dir.name) / "reg_session.pcap"

        # RegisterSession (0x0065) packet
        reg_req = struct.pack("<HHII8sI", 0x0065, 4, 0, 0, b"\x00" * 8, 0) + b"\x01\x00\x00\x00"
        pkt = Ether() / IP(src="192.168.20.100", dst="192.168.20.21") / \
              TCP(sport=49300, dport=44818) / Raw(load=reg_req)
        wrpcap(str(pcap_file), [pkt])

        summary = analyzer.analyze_pcap(pcap_file)
        sess = summary["sessions"][0]
        self.assertEqual(sess["read_count"], 0,
                         "SESSION_MGMT must not be counted as a read")
        self.assertEqual(sess["session_mgmt_count"], 1,
                         "SESSION_MGMT must increment session_mgmt_count")
        self.assertIn(sess["classification"], ("SESSION_MGMT_ONLY", "MIXED_READ_UNKNOWN", "HEADER_ONLY"))

    def test_mixed_read_unknown_classification(self):
        """A session with reads AND unsupported operations must NOT be classified READ_ONLY."""
        analyzer = PcapAnalyzer()
        pcap_file = Path(self.temp_dir.name) / "mixed.pcap"

        # FC 0x03: Read
        mbap_read = struct.pack(">HHHBB", 1, 0, 6, 1, 3) + b"\x00\x00\x00\x0a"
        pkt_read = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / \
                   TCP(sport=40001, dport=502) / Raw(load=mbap_read)
        # FC 99: Unsupported
        mbap_unsupp = struct.pack(">HHHBB", 2, 0, 6, 1, 99) + b"\xde\xad\xbe\xef"
        pkt_unsupp = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / \
                     TCP(sport=40001, dport=502) / Raw(load=mbap_unsupp)

        wrpcap(str(pcap_file), [pkt_read, pkt_unsupp])
        summary = analyzer.analyze_pcap(pcap_file)
        sess = summary["sessions"][0]
        self.assertEqual(sess["read_count"], 1)
        self.assertEqual(sess["unsupported_count"], 1)
        self.assertNotEqual(sess["classification"], "READ_ONLY",
                            "READ_ONLY must not be used when unsupported operations co-exist")
        self.assertEqual(sess["classification"], "MIXED_READ_UNKNOWN")

    # -----------------------------------------------------------------------
    # Priority 1c: Identity Ownership
    # -----------------------------------------------------------------------

    def test_modbus_fc43_identity_applied_only_to_responder(self):
        """
        FC43 identity (observed_vendor) must update only the responding endpoint (src_ip),
        not the requesting endpoint (dst_ip).
        """
        analyzer = PcapAnalyzer()
        pcap_file = Path(self.temp_dir.name) / "fc43_identity.pcap"

        plc_ip = "192.168.1.10"
        hmi_ip = "192.168.1.50"
        plc_mac = "00:80:f4:12:34:56"   # Schneider OUI
        hmi_mac = "00:50:56:fe:dc:ba"

        # FC43 response FROM the PLC (src=plc_ip) TO the HMI (dst=hmi_ip)
        vname = b"Schneider Electric"
        mname = b"BMX P34 2020"
        # MBAP length covers from Unit ID onward:
        #   Unit ID(1)+FC(1)+MEI(1)+ReadDevID(1)+Conformity(1)+More(1)+Next(1)+NumObjs(1)
        #   + 2+len(vname) + 2+len(mname) = 8 + 2+18 + 2+12 = 42
        mbap_len = 8 + 2 + len(vname) + 2 + len(mname)
        hdr43 = struct.pack(">HHHBBBBBBBB", 101, 0, mbap_len,
                            1, 43, 0x0E, 1, 1, 0, 0, 2)
        obj0 = struct.pack("BB", 0, len(vname)) + vname
        obj1 = struct.pack("BB", 1, len(mname)) + mname
        payload = hdr43 + obj0 + obj1

        pkt = (Ether(src=plc_mac, dst=hmi_mac) /
               IP(src=plc_ip, dst=hmi_ip) /
               TCP(sport=502, dport=49152) / Raw(load=payload))
        wrpcap(str(pcap_file), [pkt])

        analyzer.analyze_pcap(pcap_file)

        plc_asset = analyzer.assets.get(plc_ip)
        hmi_asset = analyzer.assets.get(hmi_ip)

        self.assertIsNotNone(plc_asset, "PLC asset must be recorded")
        self.assertIsNotNone(hmi_asset, "HMI asset must be recorded")

        # Identity must be on the responder (plc_ip), not the requester (hmi_ip)
        self.assertEqual(plc_asset.identity_evidence, "MODBUS_DEVICE_ID",
                         "PLC (responder) must have MODBUS_DEVICE_ID identity evidence")
        self.assertEqual(plc_asset.observed_vendor, "Schneider Electric",
                         "PLC (responder) must have observed_vendor set")
        self.assertNotEqual(hmi_asset.identity_evidence, "MODBUS_DEVICE_ID",
                            "HMI (requester) must NOT have MODBUS_DEVICE_ID identity evidence")
        self.assertIsNone(hmi_asset.observed_vendor,
                          "HMI (requester) observed_vendor must remain None")

    def test_cip_list_identity_applied_only_to_responder(self):
        """
        CIP ListIdentity identity (observed_vendor=Rockwell) must update only the
        responding endpoint (src_ip = the PLC), not the requesting endpoint (dst_ip = SCADA).
        """
        analyzer = PcapAnalyzer()
        pcap_file = Path(self.temp_dir.name) / "list_identity.pcap"

        plc_ip   = "192.168.20.21"
        scada_ip = "192.168.20.100"
        plc_mac  = "00:00:bc:88:99:aa"
        scada_mac = "00:50:56:fe:dc:ba"

        # ListIdentity response FROM PLC (src=plc_ip)
        pname = b"1756-L83E ControlLogix"
        encap_len = 39 + len(pname)
        encap = struct.pack("<HHII8sI", 0x0063, encap_len, 0, 0, b"\x00" * 8, 0)
        cpf_header = struct.pack("<H", 1)
        item_len = 35 + len(pname)
        item_header = struct.pack("<HH", 0x000C, item_len)
        item_data = (b"\x01\x00" + (b"\x00" * 16) +
                     struct.pack("<HHHBBHI", 1, 0x000E, 0x00A1, 32, 11, 0x0060, 0x12345678) +
                     struct.pack("B", len(pname)) + pname)
        payload = encap + cpf_header + item_header + item_data

        pkt = (Ether(src=plc_mac, dst=scada_mac) /
               IP(src=plc_ip, dst=scada_ip) /
               TCP(sport=44818, dport=49300) / Raw(load=payload))
        wrpcap(str(pcap_file), [pkt])

        analyzer.analyze_pcap(pcap_file)

        plc_asset   = analyzer.assets.get(plc_ip)
        scada_asset = analyzer.assets.get(scada_ip)

        self.assertIsNotNone(plc_asset)
        self.assertIsNotNone(scada_asset)

        self.assertEqual(plc_asset.observed_vendor, "Rockwell Automation",
                         "PLC (responder) must have Rockwell identity")
        self.assertIsNone(scada_asset.observed_vendor,
                          "SCADA (requester) observed_vendor must remain None")

    def test_umas_identity_applied_only_to_addressed_plc(self):
        """
        UMAS identity (Schneider Electric) must update only the addressed PLC (dst_ip),
        not the engineering workstation (src_ip).
        """
        analyzer = PcapAnalyzer()
        pcap_file = Path(self.temp_dir.name) / "umas_identity.pcap"

        plc_ip = "192.168.10.31"
        eng_ip = "192.168.10.50"
        plc_mac = "00:80:f4:12:34:56"
        eng_mac = "00:50:56:a1:b2:c3"

        # UMAS 0x01 Init from engineering workstation (src=eng_ip) to PLC (dst=plc_ip)
        payload = struct.pack(">HHHBB", 201, 0, 4, 1, 90) + b"\x01\x00"
        pkt = (Ether(src=eng_mac, dst=plc_mac) /
               IP(src=eng_ip, dst=plc_ip) /
               TCP(sport=50005, dport=502) / Raw(load=payload))
        wrpcap(str(pcap_file), [pkt])

        analyzer.analyze_pcap(pcap_file)

        plc_asset = analyzer.assets.get(plc_ip)
        eng_asset = analyzer.assets.get(eng_ip)

        self.assertIsNotNone(plc_asset)
        self.assertIsNotNone(eng_asset)

        self.assertEqual(plc_asset.identity_evidence, "UMAS_DECODE",
                         "PLC (dst — addressed device) must have UMAS_DECODE identity evidence")
        self.assertEqual(plc_asset.observed_vendor, "Schneider Electric",
                         "PLC (dst) must have Schneider Electric identity")
        self.assertNotEqual(eng_asset.identity_evidence, "UMAS_DECODE",
                            "Engineering workstation (src) must NOT have UMAS identity")
        self.assertIsNone(eng_asset.observed_vendor,
                          "Engineering workstation observed_vendor must remain None")

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
        # MBAP length field counts bytes from Unit ID onward:
        #   Unit ID(1)+FC(1)+MEI(1)+ReadDevID(1)+Conformity(1)+More(1)+Next(1)+NumObjs(1)
        #   + 2+len(vname) + 2+len(mname) = 8 + 20 + 14 = 42
        mbap_len = 8 + 2 + len(vname) + 2 + len(mname)
        header = struct.pack(">HHHBBBBBBBB", 1, 0, mbap_len, 1, 43, 0x0E, 1, 1, 0, 0, 2)
        obj0 = struct.pack("BB", 0, len(vname)) + vname
        obj1 = struct.pack("BB", 1, len(mname)) + mname
        payload = header + obj0 + obj1

        res = _parse_modbus(payload)
        self.assertIsNotNone(res)
        self.assertEqual(res["operation_type"], "READ")
        self.assertEqual(res["observed_vendor"], "Schneider Electric")
        self.assertEqual(res["observed_model"], "BMX P34 2020")
        self.assertEqual(res["vendor_evidence"], "MODBUS_DEVICE_ID")

    def test_modbus_truncated_frame_returns_undecoded(self):
        """Modbus frame shorter than MBAP-declared length must return UNDECODED with truncation note."""
        # MBAP declares length=10 (10 bytes from Unit ID onward) but payload has only 2 bytes after header
        payload = struct.pack(">HHHBB", 1, 0, 10, 1, 3) + b"\x00\x00"  # only 2 bytes of data
        res = _parse_modbus(payload)
        self.assertIsNotNone(res)
        self.assertEqual(res["operation_type"], "UNDECODED")
        self.assertIsNone(res["is_write"])
        self.assertIn("truncation_note", res)
        self.assertIsNone(res["function_code"])

    def test_modbus_multi_pdu_segment_parses_first_only(self):
        """Modbus payload longer than MBAP-declared length must parse only first PDU."""
        # FC 0x03 with length=6 (normal) but extra bytes appended
        fc03 = struct.pack(">HHHBB", 1, 0, 6, 1, 3) + b"\x00\x00\x00\x0a"
        # Append a second Modbus PDU (would cause confusion if both were parsed)
        fc06 = struct.pack(">HHHBB", 2, 0, 6, 1, 6) + b"\x00\x01\x12\x34"
        payload = fc03 + fc06

        res = _parse_modbus(payload)
        self.assertIsNotNone(res)
        # Must parse the first (READ) PDU only
        self.assertEqual(res["function_code"], 3)
        self.assertEqual(res["operation_type"], "READ")

    def test_schneider_umas_bounded_decoding(self):
        """
        Validate bounded UMAS subcommands:
        - 0x01 SESSION_MGMT (confirmed)
        - 0x04 WRITE (confirmed)
        - 0x50 WRITE / Stop PLC (confirmed)
        - 0x02, 0x03, 0x06, 0x20, 0x22, 0x24, 0x30: UNKNOWN (operation unverified)
        - 0x7E: UNSUPPORTED (not in known table)
        """
        # UMAS 0x01: Init Communication — SESSION_MGMT
        p_init = struct.pack(">HHHBB", 1, 0, 4, 1, 90) + b"\x01\x00"
        res_init = _parse_modbus(p_init)
        self.assertEqual(res_init["umas_code"], 0x01)
        self.assertEqual(res_init["operation_type"], "SESSION_MGMT")
        self.assertFalse(res_init["is_write"])
        self.assertEqual(res_init["observed_vendor"], "Schneider Electric")

        # UMAS 0x02: unverified — must be UNKNOWN, not READ
        p_02 = struct.pack(">HHHBB", 2, 0, 4, 1, 90) + b"\x02\x00"
        res_02 = _parse_modbus(p_02)
        self.assertEqual(res_02["umas_code"], 0x02)
        self.assertEqual(res_02["operation_type"], "UNKNOWN",
                         "UMAS 0x02 operation classification is unverified — must be UNKNOWN")
        self.assertIsNone(res_02["is_write"],
                          "UMAS 0x02 is_write must be None (unverified, not read-only)")
        self.assertEqual(res_02["observed_vendor"], "Schneider Electric",
                         "Vendor recognition must be preserved even for UNKNOWN operations")

        # UMAS 0x03: unverified — must be UNKNOWN
        p_03 = struct.pack(">HHHBB", 3, 0, 4, 1, 90) + b"\x03\x00"
        res_03 = _parse_modbus(p_03)
        self.assertEqual(res_03["operation_type"], "UNKNOWN")
        self.assertIsNone(res_03["is_write"])

        # UMAS 0x06: unverified — must be UNKNOWN
        p_06 = struct.pack(">HHHBB", 4, 0, 4, 1, 90) + b"\x06\x00"
        res_06 = _parse_modbus(p_06)
        self.assertEqual(res_06["operation_type"], "UNKNOWN")
        self.assertIsNone(res_06["is_write"])

        # UMAS 0x04: Write Internal Bits — confirmed WRITE
        p_write = struct.pack(">HHHBB", 5, 0, 6, 1, 90) + b"\x04\x00\x00\x01"
        res_write = _parse_modbus(p_write)
        self.assertEqual(res_write["umas_code"], 0x04)
        self.assertEqual(res_write["operation_type"], "WRITE")
        self.assertTrue(res_write["is_write"])

        # UMAS 0x50: Stop PLC — confirmed WRITE/CONTROL
        p_stop = struct.pack(">HHHBB", 6, 0, 4, 1, 90) + b"\x50\x00"
        res_stop = _parse_modbus(p_stop)
        self.assertEqual(res_stop["umas_code"], 0x50)
        self.assertEqual(res_stop["operation_type"], "WRITE")
        self.assertTrue(res_stop["is_write"])

        # UMAS 0x30: unverified — must be UNKNOWN
        p_30 = struct.pack(">HHHBB", 7, 0, 4, 1, 90) + b"\x30\x00"
        res_30 = _parse_modbus(p_30)
        self.assertEqual(res_30["operation_type"], "UNKNOWN")
        self.assertIsNone(res_30["is_write"])

        # UMAS 0x7E: not in known table — UNSUPPORTED
        p_unsupp = struct.pack(">HHHBB", 8, 0, 4, 1, 90) + b"\x7e\x00"
        res_unsupp = _parse_modbus(p_unsupp)
        self.assertEqual(res_unsupp["umas_code"], 0x7E)
        self.assertEqual(res_unsupp["operation_type"], "UNSUPPORTED")
        self.assertIsNone(res_unsupp["is_write"],
                          "Unsupported UMAS operation must NOT be marked False (read-only)")

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
        """
        Distinguish CIP Read Tag (0x4C) vs Write Tag (0x4D) inside SendRRData encapsulation.
        Write *requests* (bit 7 = 0) set is_write=None (outcome unconfirmed without response).
        Read requests set is_write=False.
        Unsupported services set is_write=None.
        """
        # 1. CIP Read Tag Service (0x4C) Request
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
        self.assertTrue(res_read["is_request"])
        self.assertFalse(res_read["is_response"])

        # 2. CIP Write Tag Service (0x4D) Request — is_write must be None (unconfirmed until response)
        cip_write_data = b"\x4d\x02\x20\x6b\x24\x01\xc4\x00\x01\x00\x12\x34"
        cpf_write_items = struct.pack("<HH", 0x0000, 0) + struct.pack("<HH", 0x00B2, len(cip_write_data)) + cip_write_data
        cpf_w = struct.pack("<H", 2) + cpf_write_items
        encap_write = struct.pack("<HHII8sI", 0x006F, 6 + len(cpf_w), 0x11223344, 0, b"\x00" * 8, 0) + \
                      b"\x00\x00\x00\x00\x00\x00" + cpf_w

        res_write_req = _parse_enip(encap_write)
        self.assertIsNotNone(res_write_req)
        self.assertTrue(res_write_req["cip_decoded"])
        self.assertEqual(res_write_req["cip_service_code"], 0x4D)
        self.assertEqual(res_write_req["operation_type"], "WRITE")
        # Request: outcome cannot be confirmed without matching response
        self.assertIsNone(res_write_req["is_write"],
                          "Write request is_write must be None (outcome unconfirmed without response)")
        self.assertTrue(res_write_req["is_request"])

        # 3. CIP Write Tag Service (0x4D) Successful Response — is_write must be True
        # Response: service_raw = 0x4D | 0x80 = 0xCD, reserved=0, general_status=0x00 (OK)
        cip_write_resp = b"\xcd\x00\x00"  # service_raw=0xCD (resp), reserved, status=0x00
        cpf_wr_resp_items = struct.pack("<HH", 0x0000, 0) + struct.pack("<HH", 0x00B2, len(cip_write_resp)) + cip_write_resp
        cpf_wr = struct.pack("<H", 2) + cpf_wr_resp_items
        encap_write_resp = struct.pack("<HHII8sI", 0x006F, 6 + len(cpf_wr), 0x11223344, 0, b"\x00" * 8, 0) + \
                           b"\x00\x00\x00\x00\x00\x00" + cpf_wr

        res_write_resp = _parse_enip(encap_write_resp)
        self.assertIsNotNone(res_write_resp)
        self.assertEqual(res_write_resp["cip_service_code"], 0x4D)
        self.assertEqual(res_write_resp["operation_type"], "WRITE")
        self.assertTrue(res_write_resp["is_write"],
                        "Successful write response (status=0x00) must set is_write=True")
        self.assertTrue(res_write_resp["is_response"])

        # 4. CIP Write Tag Service (0x4D) Error Response — is_write must NOT be True
        cip_write_err_resp = b"\xcd\x00\x08"  # status=0x08 (Path Destination Unknown)
        cpf_err_items = struct.pack("<HH", 0x0000, 0) + struct.pack("<HH", 0x00B2, len(cip_write_err_resp)) + cip_write_err_resp
        cpf_err = struct.pack("<H", 2) + cpf_err_items
        encap_err = struct.pack("<HHII8sI", 0x006F, 6 + len(cpf_err), 0x11223344, 0, b"\x00" * 8, 0) + \
                    b"\x00\x00\x00\x00\x00\x00" + cpf_err

        res_write_err = _parse_enip(encap_err)
        self.assertIsNotNone(res_write_err)
        self.assertEqual(res_write_err["cip_general_status"], 0x08)
        self.assertFalse(res_write_err["is_write"],
                         "Error response must NOT confirm a write (status != 0x00)")

        # 5. Unsupported CIP Service (0x3B)
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
        self.assertIsNone(res_unsupp["is_write"],
                          "Unsupported CIP service must NOT be marked False (read-only)")

    def test_cip_send_unit_data_skips_connection_sequence_number(self):
        """
        SendUnitData (0x0070) with Connected Data Item (0x00B1) must skip the
        2-byte Connection Sequence Number before interpreting the CIP service code.
        """
        # CIP Read Tag Request (0x4C) but preceded by 2-byte Connection Sequence Number
        conn_seq = b"\x01\x00"            # Connection Sequence Number (2 bytes)
        cip_read = b"\x4c\x02\x20\x6b\x24\x01\x01\x00"  # CIP Read Tag Request
        connected_item_data = conn_seq + cip_read

        # Build SendUnitData (0x0070) packet with Connected Data Item (0x00B1)
        cpf_items = (struct.pack("<HH", 0x8002, 4) + b"\x00\x00\x00\x00" +   # Connected Address Item
                     struct.pack("<HH", 0x00B1, len(connected_item_data)) + connected_item_data)
        cpf = struct.pack("<H", 2) + cpf_items
        encap = (struct.pack("<HHII8sI", 0x0070, 6 + len(cpf), 0xAABBCCDD, 0, b"\x00" * 8, 0) +
                 b"\x00\x00\x00\x00\x00\x00" + cpf)

        res = _parse_enip(encap)
        self.assertIsNotNone(res)
        self.assertTrue(res["cip_decoded"],
                        "CIP data must be decoded inside SendUnitData")
        self.assertTrue(res.get("is_connected"),
                        "is_connected must be True for Connected Data Item (0x00B1)")
        self.assertEqual(res["cip_service_code"], 0x4C,
                         "Must parse 0x4C as the CIP service code after skipping Connection Sequence Number")
        self.assertEqual(res["operation_type"], "READ")

    def test_cip_truncated_cpf_item_returns_undecoded(self):
        """CPF item claiming to extend beyond payload bounds must return UNDECODED."""
        # SendRRData with item_len declaring 100 bytes but no data following
        cpf = (struct.pack("<H", 1) +
               struct.pack("<HH", 0x00B2, 100))   # item_len=100, but no data
        encap = (struct.pack("<HHII8sI", 0x006F, 6 + len(cpf), 0, 0, b"\x00" * 8, 0) +
                 b"\x00\x00\x00\x00\x00\x00" + cpf)

        res = _parse_enip(encap)
        self.assertIsNotNone(res)
        self.assertEqual(res["operation_type"], "UNDECODED")
        self.assertIsNone(res["is_write"])

    # -----------------------------------------------------------------------
    # Priority 4: Report Boundaries (ASSESSMENT vs DEMO)
    # -----------------------------------------------------------------------

    def _minimal_report_kwargs(self, **overrides):
        """Return minimal valid kwargs for generate_markdown_report."""
        base = dict(
            client_name="Test Client",
            site_location="Test Site",
            engagement_date="2026-11-11",
            capture_duration="1 hour",
            total_packets=100,
            assets=[],
            sessions=[],
            protocol_stats={},
            findings=[],
            sl_scores={},
        )
        base.update(overrides)
        return base

    def test_invalid_mode_raises_value_error(self):
        """Invalid mode string must raise ValueError."""
        with self.assertRaises(ValueError, msg="Invalid mode must raise ValueError"):
            generate_markdown_report(**self._minimal_report_kwargs(mode="INVALID"))

    def test_assessment_mode_rejects_synthetic_inputs(self):
        """ASSESSMENT mode + is_synthetic=True must raise ValueError."""
        with self.assertRaises(ValueError,
                               msg="ASSESSMENT mode must reject synthetic inputs"):
            generate_markdown_report(**self._minimal_report_kwargs(
                mode="ASSESSMENT", is_synthetic=True))

    def test_demo_mode_accepted_with_synthetic_inputs(self):
        """DEMO mode + is_synthetic=True must succeed without error."""
        try:
            result = generate_markdown_report(**self._minimal_report_kwargs(
                mode="DEMO", is_synthetic=True))
            self.assertIn("DEMONSTRATION REPORT", result)
        except ValueError as e:
            self.fail(f"DEMO mode with is_synthetic=True raised ValueError unexpectedly: {e}")

    def test_demo_mode_accepted_without_is_synthetic(self):
        """DEMO mode without is_synthetic must also succeed (default is_synthetic=False)."""
        try:
            result = generate_markdown_report(**self._minimal_report_kwargs(mode="DEMO"))
            self.assertIn("DEMONSTRATION REPORT", result)
        except ValueError as e:
            self.fail(f"DEMO mode raised ValueError unexpectedly: {e}")

    def test_assessment_mode_accepted_with_real_data(self):
        """ASSESSMENT mode with is_synthetic=False (default) must succeed."""
        try:
            result = generate_markdown_report(**self._minimal_report_kwargs(mode="ASSESSMENT"))
            self.assertNotIn("DEMONSTRATION REPORT — SYNTHETIC / LAB-GENERATED TRAFFIC", result)
        except ValueError as e:
            self.fail(f"ASSESSMENT mode raised ValueError unexpectedly: {e}")

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
                "session_mgmt_count": 0,
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
        # Verify updated column headers (Frames, not PDUs)
        self.assertIn("Read Frames", report_md)
        self.assertIn("Write Frames", report_md)


if __name__ == "__main__":
    unittest.main()
