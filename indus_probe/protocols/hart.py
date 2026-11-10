"""
IndusProbe — HART-IP Protocol Parser

HART-IP (Highway Addressable Remote Transducer over IP)
Default Port: UDP/TCP 5094
Used by: Yokogawa, Emerson, ABB, Endress+Hauser field instruments & DCS I/O gateways.
"""

from __future__ import annotations
import struct

_HART_MESSAGE_TYPES = {
    0: "Request",
    1: "Response",
    2: "Publish",
    3: "NAK",
}

_HART_MESSAGE_IDS = {
    0: "Session Init",
    1: "Session Close",
    2: "Keep-Alive",
    3: "Pass-Through PDU",
    4: "Token-Passing PDU",
}

_HART_COMMANDS = {
    0: "Read Unique Identifier",
    1: "Read Primary Variable",
    2: "Read Loop Current and Percent of Range",
    3: "Read Dynamic Variables and Loop Current",
    6: "Write Polling Address",
    11: "Read Unique Identifier Associated With Tag",
    12: "Read Message",
    13: "Read Tag, Descriptor, Date",
    14: "Read Primary Variable Sensor Information",
    15: "Read Device Information",
    17: "Write Message",
    18: "Write Tag, Descriptor, Date",
    19: "Write Final Assembly Number",
    38: "Reset Configuration Changed Flag",
    48: "Read Additional Device Status",
}

_HART_WRITE_COMMANDS = {6, 17, 18, 19, 38}


def parse_hart_ip(payload: bytes) -> dict | None:
    """
    Parse HART-IP packet header:
      Version (1) + Msg Type (1) + Msg ID (1) + Status (1)
      + Sequence (2) + Byte Count (2) + Body
    """
    if len(payload) < 8:
        return None

    version, msg_type, msg_id, status, seq, length = struct.unpack(">BBBBHH", payload[:8])
    if version not in (1, 2):
        return None

    mtype_name = _HART_MESSAGE_TYPES.get(msg_type, f"Type-{msg_type}")
    mid_name = _HART_MESSAGE_IDS.get(msg_id, f"MsgID-{msg_id}")

    hart_cmd = None
    hart_cmd_name = ""
    is_write = False

    # If pass-through PDU, inspect HART framing
    if msg_id == 3 and len(payload) > 8:
        body = payload[8:]
        # HART frame delimiter / short or long frame
        # Byte after delimiter is delimiter-specific, search for command byte
        if len(body) >= 2:
            # Short frame: Delimiter(1), Address(1), Command(1)
            # Long frame: Delimiter(1), Address(5), Command(1)
            delimiter = body[0]
            if (delimiter & 0x80) and len(body) >= 7:  # Long frame (burst or master-slave)
                hart_cmd = body[6]
            elif len(body) >= 3:
                hart_cmd = body[2]

            if hart_cmd is not None:
                hart_cmd_name = _HART_COMMANDS.get(hart_cmd, f"Cmd-{hart_cmd}")
                is_write = hart_cmd in _HART_WRITE_COMMANDS

    return {
        "version": version,
        "message_type": mtype_name,
        "message_id": mid_name,
        "sequence": seq,
        "hart_command": hart_cmd,
        "function_name": hart_cmd_name or mid_name,
        "is_write": is_write,
    }

