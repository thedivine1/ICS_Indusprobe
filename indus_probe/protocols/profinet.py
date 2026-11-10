"""
IndusProbe — PROFINET (IO / RT / DCP / PROFIsafe) Passive Dissector

Supports:
  - PROFINET DCP (Discovery and Configuration Protocol - Layer 2 EtherType 0x8892 / UDP 34964)
  - PROFINET IO Real-Time (RT) Cyclic Data (Frame IDs 0x8000 - 0xBFFF)
  - PROFIsafe Safety Communication Frames (Frame IDs 0x0020 - 0x007F)
  - Station Name, Vendor ID, Device ID, and Cycle Time analysis

All inspection is PASSIVE — strictly reads frames from switch SPAN/mirror ports.
"""

from __future__ import annotations
import struct
from typing import Any

PROFINET_ETHERTYPE = 0x8892
PROFINET_DCP_PORT = 34964

# PROFINET Frame ID ranges
FRAME_ID_RANGES = {
    (0x0020, 0x007F): ("PROFIsafe / RT Safety", True, "CRITICAL"),
    (0x0080, 0x00FF): ("RT Cyclic High Priority", False, "MEDIUM"),
    (0x0100, 0x0FFF): ("RT Cyclic Low Priority", False, "LOW"),
    (0x8000, 0xBBFF): ("PROFINET IO RT Cyclic Data", False, "LOW"),
    (0xFC01, 0xFCFF): ("PROFINET Real-Time Alarm", False, "HIGH"),
    (0xFE01, 0xFEFF): ("PROFINET Context Manager / RTA", False, "MEDIUM"),
    (0xFEFD, 0xFEFE): ("PROFINET DCP Hello / Get / Set", True, "HIGH"),
    (0xFEFF, 0xFEFF): ("PROFINET DCP Identify / Broadcast", False, "MEDIUM"),
    (0xFF00, 0xFFFF): ("PROFINET PTCP (Time Sync / IEEE 1588)", False, "LOW"),
}

DCP_SERVICE_IDS = {
    0x05: "Get Request",
    0x06: "Set Request",
    0x07: "Identify Request",
    0x08: "Hello Request",
}

def parse_profinet_rt(payload: bytes) -> dict[str, Any] | None:
    """
    Parses PROFINET Real-Time (RT) frames (over Layer 2 or UDP).
    Frame layout:
      Frame ID (2 bytes) + Cycle Counter (2 bytes) + Data Status (1 byte) + Transfer Status (1 byte)
    """
    if len(payload) < 4:
        return None

    frame_id = struct.unpack(">H", payload[:2])[0]
    frame_type = "Unknown PROFINET Frame"
    is_safety = False
    risk_level = "LOW"

    for (start, end), (name, safety_flag, risk) in FRAME_ID_RANGES.items():
        if start <= frame_id <= end:
            frame_type = name
            is_safety = safety_flag
            risk_level = risk
            break

    result: dict[str, Any] = {
        "frame_id": hex(frame_id),
        "frame_type": frame_type,
        "is_safety": is_safety,
        "risk_level": risk_level,
        "payload_length": len(payload),
    }

    # If DCP Identify or Configuration
    if frame_id in (0xFEFD, 0xFEFE, 0xFEFF) and len(payload) >= 10:
        service_id = payload[2]
        service_type = payload[3]
        result["dcp_service"] = DCP_SERVICE_IDS.get(service_id, f"Service_{service_id}")
        result["dcp_type"] = "Request" if service_type == 0 else "Response"
        
        # Check for unauthenticated DCP Set (e.g. IP/Name reset command)
        if service_id == 0x06:
            result["is_write"] = True
            result["risk_level"] = "CRITICAL"
            result["warning"] = "PROFINET DCP Set command detected — unauthenticated IP/station name modification risk"

    # PROFIsafe frame check
    if is_safety:
        result["profisafe"] = True
        result["warning"] = "PROFIsafe safety frame observed — verify segregation from IT/corporate networks per IEC 61784-3"

    return result

