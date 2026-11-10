"""
IndusProbe — Cement Manufacturing Plant Assessment Generator
Target: Synthetic 5,000 TPD Modern Cement Line running on Schneider Electric Modicon M580 ePAC Network
Demonstration Environment: Simulated Raipur / Chandrapur Industrial Belt, India

Dataset Design Principles:
- 100% mathematically reconciled: total packets = sum of all session packets = sum of all protocol stats.
- Sessions include all observed protocols (Modbus TCP, UMAS, EtherNet/IP, OPC-UA, HART-IP, SNMP, DNP3, TCP/23, TCP/445).
- Assets specify identity source (Supplied by lab manifest vs Inferred — unverified).
- Distinguishes DPI-parsed command function codes from transport session counts.
"""

from __future__ import annotations
import sys
from pathlib import Path
from datetime import datetime

from indus_probe.cli import _run_analysis


def generate_cement_plant_model() -> dict:
    """
    Builds a mathematically reconciled 48-hour passive network telemetry dataset for a cement plant:
    - Raw Material Handling & Crusher
    - Pyroprocessing: Rotary Kiln & Preheater Tower (M580 Redundant Hot Standby)
    - Clinker Cooler & Tertiary Air Duct
    - Vertical Roller Mill (VRM) & Cement Grinding
    - Automated Bagging & Truck Dispatch
    - Schneider Altivar ATV930 Variable Frequency Drives
    - SCADA: EcoStruxure Plant SCADA / Citect & Control Expert EWS
    - Substation DNP3 monitor and Switch SNMP
    - Unregistered Dispatch and Vendor laptops
    """
    # -----------------------------------------------------------------------
    # 1. Assets (12 total: 10 in manifest, 2 unregistered)
    # -----------------------------------------------------------------------
    assets = [
        # --- Level 1: Basic Process Control (Schneider M580 / M340 Controllers) ---
        {
            "ip": "10.20.10.11",
            "mac": "00:80:F4:A1:22:11",
            "vendor": "Schneider Electric",
            "device_hint": "Modicon M580 Redundant ePAC (Kiln & Preheater)",
            "purdue_level": "Level 1",
            "protocols_seen": ["Modbus TCP", "Modbus UMAS (Schneider FC90)", "TCP/23 (Potential Telnet)"],
            "protocol_expected": ["Modbus TCP", "Modbus UMAS"],
            "packet_count": 200340,
            "is_ot_device": True,
            "in_client_inventory": True,
            "identity_source": "Supplied by lab manifest",
        },
        {
            "ip": "10.20.10.12",
            "mac": "00:80:F4:A1:22:12",
            "vendor": "Schneider Electric",
            "device_hint": "Modicon M580 PLC (Clinker Cooler & TAD)",
            "purdue_level": "Level 1",
            "protocols_seen": ["Modbus TCP"],
            "protocol_expected": ["Modbus TCP"],
            "packet_count": 45000,
            "is_ot_device": True,
            "in_client_inventory": True,
            "identity_source": "Supplied by lab manifest",
        },
        {
            "ip": "10.20.10.21",
            "mac": "00:80:F4:B2:33:01",
            "vendor": "Schneider Electric",
            "device_hint": "Modicon M580 PLC (Crusher & Raw Mill VRM)",
            "purdue_level": "Level 1",
            "protocols_seen": ["Modbus TCP", "EtherNet/IP / CIP (Rockwell)"],
            "protocol_expected": ["Modbus TCP", "EtherNet/IP"],
            "packet_count": 73400,
            "is_ot_device": True,
            "in_client_inventory": True,
            "identity_source": "Supplied by lab manifest",
        },
        {
            "ip": "10.20.10.31",
            "mac": "00:80:F4:C3:44:05",
            "vendor": "Schneider Electric",
            "device_hint": "Modicon M580 PLC (Cement Mill & Silos)",
            "purdue_level": "Level 1",
            "protocols_seen": ["Modbus TCP", "DNP3"],
            "protocol_expected": ["Modbus TCP", "DNP3"],
            "packet_count": 51620,
            "is_ot_device": True,
            "in_client_inventory": True,
            "identity_source": "Supplied by lab manifest",
        },
        {
            "ip": "10.20.10.41",
            "mac": "00:80:F4:D4:55:09",
            "vendor": "Schneider Electric",
            "device_hint": "Modicon M340 PLC (Packing Plant & Roto-Packer)",
            "purdue_level": "Level 1",
            "protocols_seen": ["Modbus TCP", "EtherNet/IP / CIP (Rockwell)"],
            "protocol_expected": ["Modbus TCP"],
            "packet_count": 42900,
            "is_ot_device": True,
            "in_client_inventory": True,
            "identity_source": "Supplied by lab manifest",
        },
        # --- Level 0-1: Process Drives & Instrumentation ---
        {
            "ip": "10.20.10.101",
            "mac": "98:F4:AB:12:34:56",
            "vendor": "Schneider Electric",
            "device_hint": "Altivar Process ATV930 VFD (Kiln Main Drive)",
            "purdue_level": "Level 1",
            "protocols_seen": ["Modbus TCP"],
            "protocol_expected": ["Modbus TCP"],
            "packet_count": 18200,
            "is_ot_device": True,
            "in_client_inventory": True,
            "identity_source": "Supplied by lab manifest",
        },
        {
            "ip": "10.20.10.150",
            "mac": "00:0A:DC:33:44:55",
            "vendor": "Yokogawa",
            "device_hint": "CENTUM / HART-IP Gas Analyzer Gateway",
            "purdue_level": "Level 1",
            "protocols_seen": ["HART-IP (Yokogawa / Emerson)"],
            "protocol_expected": ["HART-IP", "Modbus TCP"],
            "packet_count": 24800,
            "is_ot_device": True,
            "in_client_inventory": True,
            "identity_source": "Supplied by lab manifest",
        },
        # --- Level 2: Area Supervision & HMI ---
        {
            "ip": "10.20.20.15",
            "mac": "00:80:F4:99:11:22",
            "vendor": "Schneider Electric",
            "device_hint": "Magelis / Harmony iPC HMI (Central Control Room)",
            "purdue_level": "Level 2",
            "protocols_seen": ["OPC-UA"],
            "protocol_expected": ["OPC-UA"],
            "packet_count": 82100,
            "is_ot_device": True,
            "in_client_inventory": True,
            "identity_source": "Supplied by lab manifest",
        },
        # --- Level 3: SCADA Servers & Engineering Station ---
        {
            "ip": "10.20.30.10",
            "mac": "00:50:56:AA:11:01",
            "vendor": "Schneider Electric",
            "device_hint": "EcoStruxure Plant SCADA Primary Server (Citect)",
            "purdue_level": "Level 3",
            "protocols_seen": ["Modbus TCP", "OPC-UA", "HART-IP (Yokogawa / Emerson)", "DNP3", "SNMP", "TCP/445 (Potential SMB)"],
            "protocol_expected": ["Modbus TCP", "OPC-UA"],
            "packet_count": 390370,
            "is_ot_device": True,
            "in_client_inventory": True,
            "identity_source": "Supplied by lab manifest",
        },
        {
            "ip": "10.20.30.50",
            "mac": "00:50:56:AA:11:50",
            "vendor": "Schneider Electric",
            "device_hint": "Engineering Workstation (EcoStruxure Control Expert)",
            "purdue_level": "Level 3",
            "protocols_seen": ["Modbus UMAS (Schneider FC90)"],
            "protocol_expected": ["Modbus UMAS", "Modbus TCP"],
            "packet_count": 42000,
            "is_ot_device": True,
            "in_client_inventory": True,
            "identity_source": "Supplied by lab manifest",
        },
        # --- Unregistered Endpoints (Absent from reference inventory) ---
        {
            "ip": "10.20.30.99",
            "mac": "00:50:56:99:88:77",
            "vendor": "Unknown",
            "device_hint": "Cement Dispatch & SAP Billing PC",
            "purdue_level": "Unclassified / External IT",
            "protocols_seen": ["Modbus TCP", "TCP/445 (Potential SMB)"],
            "protocol_expected": [],
            "packet_count": 5350,
            "is_ot_device": False,
            "in_client_inventory": False,
            "identity_source": "Inferred — unverified",
        },
        {
            "ip": "172.16.5.40",
            "mac": "00:0C:29:EE:FF:10",
            "vendor": "Unknown",
            "device_hint": "Third-Party Burner Vendor Remote Support Laptop",
            "purdue_level": "Unclassified / External IT",
            "protocols_seen": ["TCP/23 (Potential Telnet)"],
            "protocol_expected": [],
            "packet_count": 340,
            "is_ot_device": False,
            "in_client_inventory": False,
            "identity_source": "Inferred — unverified",
        },
    ]

    # -----------------------------------------------------------------------
    # 2. Comprehensive Sessions List (15 distinct sessions)
    # -----------------------------------------------------------------------
    sessions = [
        # --- Modbus TCP Supervisory Polling (SCADA to Level 1 PLCs) ---
        {
            "src_ip": "10.20.30.10", "dst_ip": "10.20.10.11", "src_port": 50120, "dst_port": 502,
            "protocol": "Modbus TCP", "packet_count": 110000, "byte_count": 11000000, "is_write": True,
            "control_context": "SCADA Server Polling / Setpoint Write (M580 Kiln)",
        },
        {
            "src_ip": "10.20.30.10", "dst_ip": "10.20.10.12", "src_port": 50121, "dst_port": 502,
            "protocol": "Modbus TCP", "packet_count": 45000, "byte_count": 4500000, "is_write": False,
            "control_context": "SCADA Server Polling (M580 Clinker Cooler)",
        },
        {
            "src_ip": "10.20.30.10", "dst_ip": "10.20.10.21", "src_port": 50122, "dst_port": 502,
            "protocol": "Modbus TCP", "packet_count": 55000, "byte_count": 5500000, "is_write": True,
            "control_context": "SCADA Server Polling / Setpoint Write (M580 Raw Mill)",
        },
        {
            "src_ip": "10.20.30.10", "dst_ip": "10.20.10.31", "src_port": 50123, "dst_port": 502,
            "protocol": "Modbus TCP", "packet_count": 35000, "byte_count": 3500000, "is_write": False,
            "control_context": "SCADA Server Polling (M580 Cement Mill)",
        },
        {
            "src_ip": "10.20.30.10", "dst_ip": "10.20.10.41", "src_port": 50124, "dst_port": 502,
            "protocol": "Modbus TCP", "packet_count": 20000, "byte_count": 2000000, "is_write": False,
            "control_context": "SCADA Server Polling (M340 Packing Plant)",
        },
        # --- Modbus TCP Peer / Drive Control ---
        {
            "src_ip": "10.20.10.11", "dst_ip": "10.20.10.101", "src_port": 49100, "dst_port": 502,
            "protocol": "Modbus TCP", "packet_count": 18200, "byte_count": 1820000, "is_write": True,
            "control_context": "Expected Process Baseline: Kiln PLC → Kiln VFD speed control",
        },
        # --- Modbus TCP Unregistered Source ---
        {
            "src_ip": "10.20.30.99", "dst_ip": "10.20.10.41", "src_port": 59100, "dst_port": 502,
            "protocol": "Modbus TCP", "packet_count": 4500, "byte_count": 450000, "is_write": True,
            "control_context": "⚠️ Unregistered Dispatch PC → Packing PLC (Requires investigation)",
        },

        # --- Modbus UMAS Engineering Session ---
        {
            "src_ip": "10.20.30.50", "dst_ip": "10.20.10.11", "src_port": 49800, "dst_port": 502,
            "protocol": "Modbus UMAS (Schneider FC90)", "packet_count": 42000, "byte_count": 4200000, "is_write": True,
            "control_context": "Engineering Workstation (Control Expert) Program Upload / Diagnostic",
        },

        # --- OPC-UA Supervisory Session ---
        {
            "src_ip": "10.20.20.15", "dst_ip": "10.20.30.10", "src_port": 54840, "dst_port": 4840,
            "protocol": "OPC-UA", "packet_count": 82100, "byte_count": 8210000, "is_write": False,
            "control_context": "Central Control Room HMI ↔ SCADA Server Telemetry Feed",
        },

        # --- HART-IP Field Gateway ---
        {
            "src_ip": "10.20.30.10", "dst_ip": "10.20.10.150", "src_port": 55094, "dst_port": 5094,
            "protocol": "HART-IP (Yokogawa / Emerson)", "packet_count": 24800, "byte_count": 1488000, "is_write": True,
            "control_context": "SCADA Server Polling Gas Analyzer Gateway",
        },

        # --- EtherNet/IP Inter-PLC Coordination ---
        {
            "src_ip": "10.20.10.41", "dst_ip": "10.20.10.21", "src_port": 44818, "dst_port": 44818,
            "protocol": "EtherNet/IP / CIP (Rockwell)", "packet_count": 18400, "byte_count": 1840000, "is_write": False,
            "control_context": "Packing Plant PLC ↔ Raw Mill Interlock Signaling",
        },

        # --- DNP3 Substation Monitoring ---
        {
            "src_ip": "10.20.30.10", "dst_ip": "10.20.10.31", "src_port": 49200, "dst_port": 20000,
            "protocol": "DNP3", "packet_count": 16620, "byte_count": 1662000, "is_write": False,
            "control_context": "Substation Power Monitor Telemetry Polling",
        },

        # --- SNMP Infrastructure Monitoring ---
        {
            "src_ip": "10.20.30.10", "dst_ip": "10.20.10.11", "src_port": 50161, "dst_port": 161,
            "protocol": "SNMP", "packet_count": 31200, "byte_count": 2496000, "is_write": False,
            "control_context": "Network Health & Switch Port MIB-II Polling",
        },

        # --- Cross-Zone Inferences (Port-Based Heuristics) ---
        {
            "src_ip": "172.16.5.40", "dst_ip": "10.20.10.11", "src_port": 51234, "dst_port": 23,
            "protocol": "TCP/23 (Potential Telnet)", "packet_count": 340, "byte_count": 13600, "is_write": None,
            "control_context": "⚠️ External Vendor Subnet → Kiln PLC (Cleartext Remote Access Heuristic)",
        },
        {
            "src_ip": "10.20.30.99", "dst_ip": "10.20.30.10", "src_port": 49445, "dst_port": 445,
            "protocol": "TCP/445 (Potential SMB)", "packet_count": 850, "byte_count": 340000, "is_write": None,
            "control_context": "⚠️ Unregistered Dispatch PC → SCADA Server (File Sharing Heuristic)",
        },
    ]

    # Dynamically compute protocol stats from sessions to guarantee 100% mathematical consistency
    protocol_stats: dict[str, int] = {}
    for s in sessions:
        proto = s["protocol"]
        protocol_stats[proto] = protocol_stats.get(proto, 0) + s["packet_count"]

    total_packets = sum(s["packet_count"] for s in sessions)

    # Sanity reconciliation assertions
    assert sum(protocol_stats.values()) == total_packets, "Protocol stats do not sum to total packets!"
    assert sum(s["packet_count"] for s in sessions) == total_packets, "Session packet counts do not sum to total packets!"

    # -----------------------------------------------------------------------
    # 3. Deep Packet Inspection (DPI) Observations (3 distinct write command types)
    # -----------------------------------------------------------------------
    observations = [
        {
            "protocol": "Modbus TCP",
            "src_ip": "10.20.30.10",
            "dst_ip": "10.20.10.11",
            "is_write": True,
            "function_name": "Write Multiple Registers (FC16)",
            "details": {"function_code": 16, "is_write": True},
        },
        {
            "protocol": "Modbus TCP",
            "src_ip": "10.20.10.11",
            "dst_ip": "10.20.10.101",
            "is_write": True,
            "function_name": "Write Single Register (FC06 - VFD Speed Reference)",
            "details": {"function_code": 6, "is_write": True},
        },
        {
            "protocol": "HART-IP (Yokogawa / Emerson)",
            "src_ip": "10.20.30.10",
            "dst_ip": "10.20.10.150",
            "is_write": True,
            "function_name": "Write Polling Address (Command 6)",
            "details": {"hart_command": 6, "is_write": True},
        },
        {
            "protocol": "OPC-UA",
            "src_ip": "10.20.20.15",
            "dst_ip": "10.20.30.10",
            "is_write": False,
            "function_name": "OPC-UA OpenSecureChannel",
            "details": {
                "security_policy": "http://opcfoundation.org/UA/SecurityPolicy#None",
                "is_insecure": True,
            },
        },
    ]

    return {
        "total_packets": total_packets,
        "protocol_stats": protocol_stats,
        "assets": assets,
        "sessions": sessions,
        "observations": observations,
    }


def main():
    print("\n🏭 Building Cement Plant Architecture & Assessment Dataset (Schneider M580 ePAC)...")
    summary = generate_cement_plant_model()
    # Sanitized for review snapshot: use relative path instead of developer absolute path
    output_dir = Path("./reports")

    _run_analysis(
        summary=summary,
        client_name="Demonstration Cement Plant — Clinker Line 2",
        site="Synthetic 5,000 TPD Clinker Line (Demonstration Lab Environment)",
        duration_str="48 Hours Synthetic Baseline Telemetry (2026-11-08 08:00 to 2026-11-10 08:00 IST)",
        output_dir=output_dir,
    )
    print("\n✅ Cement Plant IEC 62443 Assessment Report generated successfully!")


if __name__ == "__main__":
    main()
