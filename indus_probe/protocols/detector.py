"""
IndusProbe — OT Protocol Detection (Passive / PCAP-based)

Supports:
  - Modbus TCP        (Schneider, generic)
  - Siemens S7Comm    (S7-300/400/1200/1500)
  - EtherNet/IP (CIP) (Rockwell Allen-Bradley)
  - DNP3              (Power, Water, Oil & Gas)
  - GE SRTP           (GE Fanuc PACSystems)
  - OPC-UA            (Multi-vendor SCADA)
  - PROFINET          (Siemens + others)
  - BACnet            (Building automation)
  - Modbus RTU over TCP

All detection is PASSIVE — this module only reads packets, never injects.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum


class Protocol(str, Enum):
    MODBUS_TCP   = "Modbus TCP"
    S7COMM       = "S7Comm (Siemens)"
    S7COMM_PLUS  = "S7CommPlus (Siemens S7-1200/1500)"
    ENIP_CIP     = "EtherNet/IP / CIP (Rockwell)"
    DNP3         = "DNP3"
    GE_SRTP      = "GE SRTP"
    OPC_UA       = "OPC-UA"
    HART_IP      = "HART-IP (Yokogawa / Emerson)"
    PROFINET     = "PROFINET"
    BACNET       = "BACnet/IP"
    IEC104       = "IEC 60870-5-104"
    MQTT         = "MQTT (IoT/SCADA)"
    UNKNOWN      = "Unknown"


# Well-known ICS ports
PORT_MAP: dict[int, Protocol] = {
    502:   Protocol.MODBUS_TCP,
    102:   Protocol.S7COMM,
    44818: Protocol.ENIP_CIP,
    2222:  Protocol.ENIP_CIP,       # EtherNet/IP I/O (UDP)
    20000: Protocol.DNP3,
    18245: Protocol.GE_SRTP,
    4840:  Protocol.OPC_UA,
    5094:  Protocol.HART_IP,
    47808: Protocol.BACNET,
    2404:  Protocol.IEC104,
    1883:  Protocol.MQTT,
    8883:  Protocol.MQTT,
    34962: Protocol.PROFINET,
    34963: Protocol.PROFINET,
    34964: Protocol.PROFINET,
}

# PROFINET uses EtherType 0x8892 (layer 2, not IP-based)
PROFINET_ETHERTYPE = 0x8892


@dataclass
class ProtocolObservation:
    protocol: Protocol
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    src_mac: str = ""
    dst_mac: str = ""
    function_code: int | None = None
    function_name: str = ""
    operation_type: str = "UNDECODED"  # READ, WRITE, SESSION_MGMT, ROUTING, UNSUPPORTED, UNDECODED
    is_write: bool | None = False      # True = confirmed write, False = confirmed read, None = unverified/unsupported
    is_authenticated: bool = False     # Does this session show auth exchange?
    observed_vendor: str | None = None
    observed_model: str | None = None
    vendor_evidence: str = "NONE"       # CIP_IDENTITY, MODBUS_DEVICE_ID, UMAS_DECODE, NONE
    details: dict = field(default_factory=dict)
    packet_count: int = 1


# ---------------------------------------------------------------------------
# Per-protocol parsers  (all return None if bytes don't match)
# ---------------------------------------------------------------------------

def _parse_modbus(payload: bytes) -> dict | None:
    """
    Modbus Application Protocol (MBAP) header:
      Transaction ID (2) + Protocol ID (2, must be 0x0000)
      + Length (2) + Unit ID (1) + Function Code (1) + data
    """
    if len(payload) < 8:
        return None
    tid, proto_id, length, unit_id, fc = struct.unpack(">HHHBB", payload[:8])
    if proto_id != 0x0000:
        return None

    _STD_FCS = {
        1:  ("Read Coils", "READ", False),
        2:  ("Read Discrete Inputs", "READ", False),
        3:  ("Read Holding Registers", "READ", False),
        4:  ("Read Input Registers", "READ", False),
        5:  ("Write Single Coil", "WRITE", True),
        6:  ("Write Single Register", "WRITE", True),
        15: ("Write Multiple Coils", "WRITE", True),
        16: ("Write Multiple Registers", "WRITE", True),
        17: ("Report Slave ID", "READ", False),
        22: ("Mask Write Register", "WRITE", True),
        23: ("Read/Write Multiple Registers", "WRITE", True),
    }

    # FC 43 (0x2B): Read Device Identification (Encapsulated Interface Transport)
    if fc == 43:
        details = {
            "transaction_id": tid,
            "unit_id": unit_id,
            "function_code": fc,
            "function_name": "Read Device Identification",
            "operation_type": "READ",
            "is_write": False,
            "length": length,
            "vendor_evidence": "MODBUS_DEVICE_ID",
        }
        # Parse MEI response objects if available
        # Header: MEI Type (1B, 0x0E), Read Device ID (1B), Conformity (1B), More (1B), Next (1B), Num Objects (1B)
        if len(payload) > 14 and payload[8] == 0x0E:
            try:
                num_objs = payload[13]
                idx = 14
                for _ in range(num_objs):
                    if idx + 2 > len(payload):
                        break
                    obj_id = payload[idx]
                    obj_len = payload[idx + 1]
                    idx += 2
                    if idx + obj_len > len(payload):
                        break
                    val = payload[idx:idx + obj_len].decode("latin-1", errors="replace").strip()
                    idx += obj_len
                    if obj_id == 0:
                        details["observed_vendor"] = val
                    elif obj_id == 1:
                        details["observed_model"] = val
                    elif obj_id == 2:
                        details["observed_firmware"] = val
            except Exception:
                pass
        return details

    # FC 90 (0x5A): Schneider UMAS (Modicon Unity/M340/M580 proprietary service)
    if fc == 90:
        umas_code = payload[8] if len(payload) > 8 else None
        _UMAS_FUNCTIONS = {
            0x01: ("UMAS Init Communication / Assign Session", "SESSION_MGMT", False),
            0x02: ("UMAS Read Memory Block / Read PLC Info", "READ", False),
            0x03: ("UMAS Read Internal Bits / Registers", "READ", False),
            0x04: ("UMAS Write Internal Bits / Registers", "WRITE", True),
            0x06: ("UMAS Read System Bits", "READ", False),
            0x07: ("UMAS Write System Bits", "WRITE", True),
            0x20: ("UMAS Read Memory Card / Backup", "READ", False),
            0x22: ("UMAS Read Project Info", "READ", False),
            0x24: ("UMAS Read Variable Info", "READ", False),
            0x30: ("UMAS Read Executive / Hardware ID", "READ", False),
            0x50: ("UMAS Stop PLC", "WRITE", True),
            0x58: ("UMAS Start PLC", "WRITE", True),
        }

        if umas_code in _UMAS_FUNCTIONS:
            fname, op_type, is_wr = _UMAS_FUNCTIONS[umas_code]
            return {
                "transaction_id": tid,
                "unit_id": unit_id,
                "function_code": fc,
                "umas_code": umas_code,
                "function_name": fname,
                "operation_type": op_type,
                "is_write": is_wr,
                "length": length,
                "observed_vendor": "Schneider Electric",
                "vendor_evidence": "UMAS_DECODE",
            }
        else:
            # Explicitly mark unsupported UMAS operations as unknown/unsupported, NOT read-only
            sub_hex = f"0x{umas_code:02X}" if umas_code is not None else "Truncated"
            return {
                "transaction_id": tid,
                "unit_id": unit_id,
                "function_code": fc,
                "umas_code": umas_code,
                "function_name": f"UMAS Unsupported Subcommand ({sub_hex})",
                "operation_type": "UNSUPPORTED",
                "is_write": None,  # Not read-only
                "length": length,
                "observed_vendor": "Schneider Electric",
                "vendor_evidence": "UMAS_DECODE",
            }

    if fc in _STD_FCS:
        fname, op_type, is_wr = _STD_FCS[fc]
        return {
            "transaction_id": tid,
            "unit_id": unit_id,
            "function_code": fc,
            "function_name": fname,
            "operation_type": op_type,
            "is_write": is_wr,
            "length": length,
        }

    # Unsupported Modbus function code
    return {
        "transaction_id": tid,
        "unit_id": unit_id,
        "function_code": fc,
        "function_name": f"Modbus Unsupported Function Code ({fc})",
        "operation_type": "UNSUPPORTED",
        "is_write": None,  # Not read-only
        "length": length,
    }


def _parse_s7(payload: bytes) -> dict | None:
    """
    S7Comm lives inside TPKT + COTP + S7 layers.
    TPKT: 0x03 0x00 (version 3) + length(2)
    COTP: varies
    S7:   protocol_id = 0x32
    """
    if len(payload) < 4:
        return None
    # TPKT check
    if payload[0] != 0x03 or payload[1] != 0x00:
        return None
    if len(payload) < 10:
        return None

    # Skip TPKT (4 bytes) + COTP header (variable, starts at byte 4)
    cotp_len = payload[4]           # COTP header length field
    s7_start = 4 + cotp_len + 1
    if s7_start + 2 > len(payload):
        return None

    if payload[s7_start] != 0x32:   # S7 protocol magic
        return None

    msg_type = payload[s7_start + 1]
    _MSG_TYPES = {
        1: "Job Request",
        2: "Ack",
        3: "Ack-Data (Response)",
        7: "UserData (Diagnostic/Time/Prog)",
    }

    is_plus = len(payload) > s7_start + 10 and payload[s7_start + 10] in (0x72, 0x73)

    return {
        "message_type": msg_type,
        "message_type_name": _MSG_TYPES.get(msg_type, f"Type-{msg_type}"),
        "is_s7plus": is_plus,  # S7CommPlus = S7-1200/1500 (encrypted in newer FW)
        "protocol_version": "S7CommPlus" if is_plus else "S7Comm",
    }


def _parse_enip(payload: bytes) -> dict | None:
    """
    EtherNet/IP encapsulation header (24 bytes):
      Command (2) + Length (2) + Session Handle (4)
      + Status (4) + Sender Context (8) + Options (4)
    Followed by encapsulated command data (CPF or ListIdentity).
    Purely passive — never injects packets.
    """
    if len(payload) < 24:
        return None

    cmd, length, session, status = struct.unpack("<HHII", payload[:12])

    _ENIP_CMDS = {
        0x0004: ("List Services", "SESSION_MGMT", False),
        0x0063: ("List Identity", "READ", False),
        0x0064: ("List Interfaces", "SESSION_MGMT", False),
        0x0065: ("Register Session", "SESSION_MGMT", False),
        0x0066: ("Unregister Session", "SESSION_MGMT", False),
        0x006F: ("Send RR Data", "CIP_ENCAP", None),
        0x0070: ("Send Unit Data", "CIP_ENCAP", None),
    }
    if cmd not in _ENIP_CMDS:
        return None

    cmd_name, base_op, is_wr = _ENIP_CMDS[cmd]
    details: dict = {
        "command": cmd,
        "command_name": cmd_name,
        "function_name": cmd_name,
        "session_handle": session,
        "status": status,
        "length": length,
        "operation_type": base_op,
        "is_write": is_wr,
        "cip_decoded": False,
    }

    # List Identity (0x0063) response decoding
    if cmd == 0x0063:
        details["operation_type"] = "READ"
        details["is_write"] = False
        if len(payload) >= 30:
            try:
                # CPF starts at byte 24: Item Count (uint16)
                item_count = struct.unpack("<H", payload[24:26])[0]
                idx = 26
                for _ in range(item_count):
                    if idx + 4 > len(payload):
                        break
                    item_type, item_len = struct.unpack("<HH", payload[idx:idx + 4])
                    idx += 4
                    if item_type == 0x000C:  # Identity Item
                        data = payload[idx:idx + item_len]
                        # Identity item layout:
                        # 0..1: Encapsulation version (2B)
                        # 2..17: Socket Address (16B)
                        # 18..19: Vendor ID (2B uint16 LE) -> 1 = Rockwell Automation
                        # 20..21: Device Type (2B uint16 LE)
                        # 22..23: Product Code (2B uint16 LE)
                        # 24: Revision Major (1B), 25: Revision Minor (1B)
                        # 26..27: Status (2B uint16 LE)
                        # 28..31: Serial Number (4B uint32 LE)
                        # 32: Product Name Length (1B)
                        # 33..: Product Name String
                        if len(data) >= 33:
                            vendor_id, dev_type, prod_code, rev_maj, rev_min, dev_status, serial = struct.unpack(
                                "<HHHBBHI", data[18:32]
                            )
                            name_len = data[32]
                            prod_name = data[33:33 + name_len].decode("latin-1", errors="replace").strip()
                            details["vendor_id"] = vendor_id
                            details["device_type"] = dev_type
                            details["product_code"] = prod_code
                            details["revision"] = f"{rev_maj}.{rev_min}"
                            details["serial_number"] = f"0x{serial:08X}"
                            details["product_name"] = prod_name
                            if vendor_id == 1:
                                details["observed_vendor"] = "Rockwell Automation"
                                details["observed_model"] = prod_name or "Allen-Bradley Controller"
                                details["observed_firmware"] = f"v{rev_maj}.{rev_min}"
                                details["vendor_evidence"] = "CIP_IDENTITY"
                            elif prod_name:
                                details["observed_model"] = prod_name
                                details["vendor_evidence"] = "CIP_IDENTITY"
                    idx += item_len
            except Exception:
                pass
        return details

    # CIP Encapsulation: SendRRData (0x006F) & SendUnitData (0x0070)
    if cmd in (0x006F, 0x0070):
        # Encap Header (24B) + Interface Handle (4B) + Timeout (2B) = 30 bytes minimum
        if len(payload) < 32:
            details["operation_type"] = "UNDECODED"
            details["is_write"] = None
            details["function_name"] = f"{cmd_name} (Truncated Header)"
            return details

        try:
            # Common Packet Format (CPF) starts at byte 30
            item_count = struct.unpack("<H", payload[30:32])[0]
            idx = 32
            data_item_payload = None

            for _ in range(item_count):
                if idx + 4 > len(payload):
                    break
                item_type, item_len = struct.unpack("<HH", payload[idx:idx + 4])
                idx += 4
                # 0x00B2: Unconnected Data Item; 0x00B1: Connected Data Item
                if item_type in (0x00B2, 0x00B1):
                    data_item_payload = payload[idx:idx + item_len]
                    break
                idx += item_len

            if data_item_payload and len(data_item_payload) > 0:
                details["cip_decoded"] = True
                service_raw = data_item_payload[0]
                is_response = bool(service_raw & 0x80)
                service_code = service_raw & 0x7F

                _CIP_SERVICES = {
                    0x01: ("Get Attributes All", "READ", False),
                    0x02: ("Set Attributes All", "WRITE", True),
                    0x03: ("Get Attribute List", "READ", False),
                    0x04: ("Set Attribute List", "WRITE", True),
                    0x0E: ("Get Attribute Single", "READ", False),
                    0x10: ("Set Attribute Single", "WRITE", True),
                    0x4C: ("CIP Read Tag Service", "READ", False),
                    0x4D: ("CIP Write Tag Service", "WRITE", True),
                    0x4E: ("CIP Write Tag Fragmented / Read-Modify-Write", "WRITE", True),
                    0x52: ("CIP Unconnected Send", "ROUTING", None),
                    0x54: ("CIP Forward Open", "SESSION_MGMT", False),
                }

                suffix = " Response" if is_response else " Request"
                details["cip_service_code"] = service_code
                details["is_response"] = is_response

                if service_code in _CIP_SERVICES:
                    sname, op_type, is_wr = _CIP_SERVICES[service_code]
                    details["function_name"] = sname + suffix
                    details["operation_type"] = op_type
                    details["is_write"] = is_wr
                else:
                    # Unsupported CIP service code - explicitly NOT read-only
                    details["function_name"] = f"CIP Service 0x{service_code:02X}" + suffix
                    details["operation_type"] = "UNSUPPORTED"
                    details["is_write"] = None
            else:
                details["operation_type"] = "UNDECODED"
                details["is_write"] = None
                details["function_name"] = f"{cmd_name} (Missing CIP Data Item)"
        except Exception:
            details["operation_type"] = "UNDECODED"
            details["is_write"] = None
            details["function_name"] = f"{cmd_name} (Malformed CPF)"

        return details

    return details


def _parse_dnp3(payload: bytes) -> dict | None:
    """
    DNP3 Data Link Layer:
      Start bytes: 0x05 0x64
    """
    if len(payload) < 10:
        return None
    if payload[0] != 0x05 or payload[1] != 0x64:
        return None

    length = payload[2]
    control = payload[3]
    dst_addr = struct.unpack("<H", payload[4:6])[0]
    src_addr = struct.unpack("<H", payload[6:8])[0]

    return {
        "dnp3_src": src_addr,
        "dnp3_dst": dst_addr,
        "control_byte": control,
        "data_length": length,
    }


def _parse_ge_srtp(payload: bytes) -> dict | None:
    """
    GE SRTP (Service Request Transport Protocol)
    Default port: 18245
    Magic: starts with 0x26 or specific header pattern
    """
    if len(payload) < 8:
        return None
    # GE SRTP request frame starts with specific byte patterns
    if payload[0] in (0x00, 0x06, 0x07) and payload[1] in (0x00, 0x01):
        _SRTP_SERVICES = {
            0x00: "Read Program Data",
            0x01: "Write Program Data",
            0x06: "Read System Memory",
            0x07: "Write System Memory",
            0x26: "Service Request",
        }
        svc = payload[0]
        return {
            "service": svc,
            "service_name": _SRTP_SERVICES.get(svc, f"SVC-{svc:#04x}"),
            "is_write": svc in {0x01, 0x07},
        }
    return None


# ---------------------------------------------------------------------------
# Main detection function
# ---------------------------------------------------------------------------

def detect_protocol_from_payload(
    payload: bytes,
    dst_port: int,
    src_port: int,
) -> tuple[Protocol, dict]:
    """
    Try to identify the OT protocol from TCP/UDP payload bytes.
    Returns (Protocol, details_dict).
    Pure passive — no network calls.
    """
    # Port-based fast-path
    port_proto = PORT_MAP.get(dst_port) or PORT_MAP.get(src_port)

    if dst_port == 502 or src_port == 502:
        parsed = _parse_modbus(payload)
        if parsed:
            return Protocol.MODBUS_TCP, parsed

    if dst_port == 102 or src_port == 102:
        parsed = _parse_s7(payload)
        if parsed:
            proto = Protocol.S7COMM_PLUS if parsed.get("is_s7plus") else Protocol.S7COMM
            return proto, parsed

    if dst_port in (44818, 2222) or src_port in (44818, 2222):
        parsed = _parse_enip(payload)
        if parsed:
            return Protocol.ENIP_CIP, parsed

    if dst_port == 20000 or src_port == 20000:
        parsed = _parse_dnp3(payload)
        if parsed:
            return Protocol.DNP3, parsed

    if dst_port == 18245 or src_port == 18245:
        parsed = _parse_ge_srtp(payload)
        if parsed:
            return Protocol.GE_SRTP, parsed

    if dst_port == 5094 or src_port == 5094:
        from indus_probe.protocols.hart import parse_hart_ip
        parsed = parse_hart_ip(payload)
        if parsed:
            return Protocol.HART_IP, parsed

    if dst_port == 4840 or src_port == 4840:
        from indus_probe.protocols.opc_ua import parse_opc_ua
        parsed = parse_opc_ua(payload)
        if parsed:
            return Protocol.OPC_UA, parsed

    if dst_port in (34962, 34963, 34964) or src_port in (34962, 34963, 34964):
        from indus_probe.protocols.profinet import parse_profinet_rt
        parsed = parse_profinet_rt(payload)
        if parsed:
            return Protocol.PROFINET, parsed

    if port_proto:
        return port_proto, {}

    return Protocol.UNKNOWN, {}


def is_write_command(protocol: Protocol, details: dict) -> bool | None:
    """
    Return True if this observation represents a confirmed write/command to a device.
    Return False if confirmed read or read-only session management.
    Return None if unverified, unsupported, or undecoded.
    """
    return details.get("is_write", None)

