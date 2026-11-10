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
    is_write: bool = False          # True = write/command to device (higher risk)
    is_authenticated: bool = False  # Does this session show auth exchange?
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

    _FC_NAMES = {
        1:  "Read Coils",
        2:  "Read Discrete Inputs",
        3:  "Read Holding Registers",
        4:  "Read Input Registers",
        5:  "Write Single Coil",
        6:  "Write Single Register",
        15: "Write Multiple Coils",
        16: "Write Multiple Registers",
        17: "Report Slave ID",
        23: "Read/Write Multiple Registers",
        43: "Read Device Identification",
        90: "Encapsulated Transport (Modicon Unity)",
    }
    _WRITE_FCS = {5, 6, 15, 16, 22, 23}

    return {
        "transaction_id": tid,
        "unit_id": unit_id,
        "function_code": fc,
        "function_name": _FC_NAMES.get(fc, f"FC{fc}"),
        "is_write": fc in _WRITE_FCS,
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
    EtherNet/IP encapsulation header:
      Command (2) + Length (2) + Session Handle (4)
      + Status (4) + Sender Context (8) + Options (4)
    """
    if len(payload) < 24:
        return None

    cmd, length, session, status = struct.unpack("<HHII", payload[:12])

    _ENIP_CMDS = {
        0x0004: "List Services",
        0x0063: "List Identity",
        0x0064: "List Interfaces",
        0x0065: "Register Session",
        0x0066: "Unregister Session",
        0x0070: "Send RR Data (Explicit Msg)",
        0x006F: "Send Unit Data (Implicit I/O)",
    }
    if cmd not in _ENIP_CMDS:
        return None

    _WRITE_CMDS = {0x0070, 0x006F}

    return {
        "command": cmd,
        "command_name": _ENIP_CMDS.get(cmd, f"CMD-{cmd:#06x}"),
        "session_handle": session,
        "is_write": cmd in _WRITE_CMDS,
    }


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


def is_write_command(protocol: Protocol, details: dict) -> bool:
    """Return True if this observation represents a write/command to a device."""
    return bool(details.get("is_write", False))

