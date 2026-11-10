"""
IndusProbe — OUI / MAC-to-Vendor Fingerprinting

Known industrial OUIs for Siemens, Rockwell, Schneider, GE, Yokogawa,
Honeywell, ABB, Emerson, Mitsubishi, and others.
"""

from __future__ import annotations
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# OUI prefix → (vendor_name, device_type_hint, purdue_level)
# Source: IEEE OUI registry + ICS-specific extensions
# ---------------------------------------------------------------------------
_OUI_DB: dict[str, tuple[str, str, str]] = {
    # Siemens
    "00:1B:1B": ("Siemens", "S7 PLC / SIMATIC", "Level 1-2"),
    "00:0E:8C": ("Siemens", "SIMATIC / SINUMERIK", "Level 1-2"),
    "28:63:36": ("Siemens", "SIMATIC S7-1200/1500", "Level 1"),
    "AC:64:17": ("Siemens", "SIMATIC S7-1500", "Level 1"),
    "00:50:49": ("Siemens", "SCALANCE Switch / Router", "Level 2"),
    "98:48:27": ("Siemens", "SCALANCE / Industrial Switch", "Level 2"),

    # Rockwell Automation / Allen-Bradley
    "00:00:BC": ("Rockwell Automation", "ControlLogix / CompactLogix PLC", "Level 1"),
    "00:08:28": ("Rockwell Automation", "ControlLogix", "Level 1"),
    "00:0D:88": ("Rockwell Automation", "PLC / Drive", "Level 1"),
    "00:50:04": ("Rockwell Automation", "Allen-Bradley Device", "Level 1-2"),
    "EC:CD:6D": ("Rockwell Automation", "Stratix Switch", "Level 2"),
    "00:0D:88": ("Rockwell Automation", "Allen-Bradley", "Level 1"),

    # Schneider Electric
    "00:80:F4": ("Schneider Electric", "Modicon M340/M580/Premium PLC", "Level 1"),
    "00:60:65": ("Schneider Electric", "Quantum / Premium PLC", "Level 1"),
    "00:0C:DB": ("Schneider Electric", "ConneXium Switch", "Level 2"),
    "98:F4:AB": ("Schneider Electric", "Altivar Drive / Magelis HMI", "Level 1-2"),
    "50:4E:DC": ("Schneider Electric", "PowerLogic / APC", "Level 2-3"),

    # GE / GE Fanuc / GE Vernova
    "00:1D:D8": ("GE Fanuc", "PACSystems RX3i / RSTi PLC", "Level 1"),
    "00:30:DA": ("GE Digital", "GE SCADA / iHistorian", "Level 3"),
    "00:0B:C2": ("GE", "GE Multilin Relay", "Level 1"),
    "78:DA:07": ("GE Vernova", "GE PLC / RTU", "Level 1"),

    # Yokogawa
    "00:0A:DC": ("Yokogawa", "CENTUM VP / ProSafe DCS", "Level 1-2"),
    "00:17:01": ("Yokogawa", "STARDOM / Vnet/IP Controller", "Level 1"),
    "00:50:01": ("Yokogawa", "Yokogawa Field Device", "Level 0-1"),

    # Honeywell
    "00:04:48": ("Honeywell", "Experion PKS / C300 DCS", "Level 1-2"),
    "00:50:F1": ("Honeywell", "Experion Server", "Level 2-3"),
    "00:40:84": ("Honeywell", "Safety Manager / FSC", "Level 1"),

    # ABB
    "00:30:11": ("ABB", "AC500 PLC / 800xA DCS", "Level 1-2"),
    "00:04:AB": ("ABB", "ABB Industrial Device", "Level 1"),
    "F4:CE:46": ("ABB", "ABB Drives / Motors", "Level 1"),

    # Emerson / Fisher / DeltaV
    "00:03:9D": ("Emerson", "DeltaV DCS", "Level 1-2"),
    "00:04:9E": ("Emerson", "DeltaV / ROC RTU", "Level 1"),
    "00:00:88": ("Emerson", "Emerson Fisher Device", "Level 0-1"),

    # Mitsubishi Electric
    "08:00:06": ("Mitsubishi Electric", "MELSEC iQ-R / Q Series PLC", "Level 1"),
    "00:0D:52": ("Mitsubishi Electric", "MELSEC PLC", "Level 1"),

    # Phoenix Contact
    "00:A0:45": ("Phoenix Contact", "RFC / ILC Controller", "Level 1-2"),
    "00:50:DC": ("Phoenix Contact", "FL Switch / AXIOLINE", "Level 2"),

    # Moxa (Industrial Networking)
    "00:90:E8": ("Moxa", "Industrial Switch / Serial Server", "Level 2"),
    "44:39:C4": ("Moxa", "Moxa Networking", "Level 2"),

    # Beckhoff
    "00:01:05": ("Beckhoff", "CX / BK EtherCAT Controller", "Level 1-2"),
    "50:ED:97": ("Beckhoff", "EtherCAT Device", "Level 1"),

    # Hirschmann (Belden)
    "00:00:38": ("Hirschmann / Belden", "RS/MACH Industrial Switch", "Level 2"),
    "5C:26:0A": ("Hirschmann", "Rail Switch / OpenRail", "Level 2"),

    # Cisco (IT switches found in OT)
    "00:00:0C": ("Cisco", "Catalyst / Stratix Switch (IT-grade)", "Level 2-3"),
    "00:1A:A2": ("Cisco", "Cisco Industrial Switch", "Level 2"),

    # Generic / Unknown
    "FF:FF:FF": ("Broadcast", "Broadcast Address", "N/A"),
}

@dataclass
class VendorInfo:
    mac: str
    oui: str
    vendor: str
    device_hint: str
    purdue_level: str
    is_ot_device: bool
    protocol_expected: list[str] = field(default_factory=list)

_OT_VENDORS = {
    "Siemens", "Rockwell Automation", "Schneider Electric",
    "GE Fanuc", "GE Digital", "GE Vernova", "GE",
    "Yokogawa", "Honeywell", "ABB", "Emerson",
    "Mitsubishi Electric", "Phoenix Contact", "Beckhoff",
    "Hirschmann / Belden", "Hirschmann", "Moxa",
}

_VENDOR_PROTOCOLS: dict[str, list[str]] = {
    "Siemens":          ["S7Comm", "S7CommPlus", "PROFINET"],
    "Rockwell Automation": ["EtherNet/IP", "CIP", "PCCC"],
    "Schneider Electric":  ["Modbus TCP", "EtherNet/IP", "Unity protocol"],
    "GE Fanuc":         ["GE SRTP", "EtherNet/IP"],
    "GE Digital":       ["GE SRTP", "DNP3"],
    "Yokogawa":         ["Vnet/IP", "HART", "Modbus TCP"],
    "Honeywell":        ["FTE", "OPC-DA", "Modbus"],
    "ABB":              ["PROFIBUS", "Modbus TCP", "OPC-UA"],
    "Emerson":          ["HART", "Foundation Fieldbus", "Modbus"],
    "Mitsubishi Electric": ["MELSEC", "CC-Link", "Modbus TCP"],
}


def lookup_oui(mac: str) -> VendorInfo:
    """Return vendor information for a MAC address string (any separator)."""
    cleaned = mac.upper().replace("-", ":").replace(".", ":")
    # Normalize to xx:xx:xx
    parts = cleaned.split(":")
    if len(parts) >= 3:
        oui = ":".join(parts[:3])
    else:
        oui = "UNKNOWN"

    if oui in _OUI_DB:
        vendor, hint, level = _OUI_DB[oui]
    else:
        vendor, hint, level = "Unknown", "Unknown Device", "Unknown"

    is_ot = vendor in _OT_VENDORS
    expected_protocols = _VENDOR_PROTOCOLS.get(vendor, [])

    return VendorInfo(
        mac=mac,
        oui=oui,
        vendor=vendor,
        device_hint=hint,
        purdue_level=level,
        is_ot_device=is_ot,
        protocol_expected=expected_protocols,
    )


def all_known_oui_prefixes() -> list[str]:
    return list(_OUI_DB.keys())

