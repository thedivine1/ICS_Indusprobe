"""
IndusProbe — PCAP Loader & Passive Capture Engine

Reads .pcap/.pcapng files OR live-captures from a network interface.
NEVER injects packets — purely passive / listen-only.
"""

from __future__ import annotations

import os
import sys
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from indus_probe.fingerprint import lookup_oui, VendorInfo
from indus_probe.protocols.detector import (
    Protocol, ProtocolObservation,
    detect_protocol_from_payload, is_write_command,
)

logger = logging.getLogger(__name__)


@dataclass
class Asset:
    ip: str
    mac: str
    vendor_info: VendorInfo
    protocols_seen: set[str] = field(default_factory=set)
    purdue_level: str = "Unknown"
    packet_count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    in_client_inventory: bool = True   # set False if not in client list

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor_info.vendor,
            "device_hint": self.vendor_info.device_hint,
            "purdue_level": self.vendor_info.purdue_level,
            "protocols_seen": list(self.protocols_seen),
            "protocol_expected": self.vendor_info.protocol_expected,
            "packet_count": self.packet_count,
            "is_ot_device": self.vendor_info.is_ot_device,
            "in_client_inventory": self.in_client_inventory,
        }


@dataclass
class Session:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int = 1
    byte_count: int = 0
    is_write: bool = False

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "is_write": self.is_write,
        }


class PcapAnalyzer:
    """
    Passive PCAP/live-capture analyzer.
    Requires pyshark (tshark) for packet parsing.
    """

    def __init__(self, known_assets: list[str] | None = None):
        self.assets: dict[str, Asset] = {}
        self.sessions: dict[tuple, Session] = {}
        self.observations: list[dict] = []
        self.protocol_stats: dict[str, int] = defaultdict(int)
        self.known_assets = set(known_assets or [])
        self._packet_count = 0

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def analyze_pcap(self, pcap_path: str | Path) -> dict:
        """Analyze a PCAP/PCAPNG file. Returns summary dict."""
        path = Path(pcap_path)
        if not path.exists():
            raise FileNotFoundError(f"PCAP not found: {path}")

        logger.info(f"Analyzing {path.name} ...")
        try:
            import pyshark
            cap = pyshark.FileCapture(
                str(path),
                display_filter="tcp or udp",
                use_json=True,
                include_raw=True,
            )
            for pkt in cap:
                self._process_pyshark_packet(pkt)
            cap.close()
            return self._build_summary()
        except Exception as e:
            logger.warning(f"pyshark/tshark error ({e}) — falling back to scapy engine")
            return self._analyze_pcap_scapy(path)

    def analyze_live(self, interface: str, duration_seconds: int = 60) -> dict:
        """
        Passive live capture on the specified interface.
        SAFETY: capture-only, no packets sent.
        """
        try:
            import pyshark
        except ImportError:
            raise RuntimeError("pyshark required for live capture: pip install pyshark")

        logger.info(
            f"[PASSIVE] Starting {duration_seconds}s capture on {interface}. "
            f"NO packets will be transmitted."
        )
        cap = pyshark.LiveCapture(
            interface=interface,
            display_filter="tcp or udp",
        )
        cap.sniff(timeout=duration_seconds)
        for pkt in cap:
            self._process_pyshark_packet(pkt)

        return self._build_summary()

    # -------------------------------------------------------------------
    # Packet processing
    # -------------------------------------------------------------------

    def _process_pyshark_packet(self, pkt) -> None:
        try:
            self._packet_count += 1
            src_ip = str(getattr(getattr(pkt, "ip", None), "src", ""))
            dst_ip = str(getattr(getattr(pkt, "ip", None), "dst", ""))
            src_mac = str(getattr(getattr(pkt, "eth", None), "src", ""))
            dst_mac = str(getattr(getattr(pkt, "eth", None), "dst", ""))

            # Layer 4 ports
            tcp = getattr(pkt, "tcp", None)
            udp = getattr(pkt, "udp", None)
            transport = tcp or udp
            if not transport:
                return

            src_port = int(getattr(transport, "srcport", 0))
            dst_port = int(getattr(transport, "dstport", 0))
            pkt_len  = int(getattr(pkt, "length", 0))

            # Try to get application-layer raw payload
            payload = b""
            try:
                raw = pkt.get_raw_packet()
                payload = raw[-min(256, len(raw)):]  # last 256 bytes
            except Exception:
                pass

            # Protocol detection
            proto, details = detect_protocol_from_payload(payload, dst_port, src_port)
            write_flag = is_write_command(proto, details)

            # Update assets
            if src_ip and src_mac:
                self._upsert_asset(src_ip, src_mac, proto.value)
            if dst_ip and dst_mac:
                self._upsert_asset(dst_ip, dst_mac, proto.value)

            # Update sessions
            if src_ip and dst_ip and proto != Protocol.UNKNOWN:
                session_key = (src_ip, dst_ip, proto.value, dst_port)
                if session_key in self.sessions:
                    self.sessions[session_key].packet_count += 1
                    self.sessions[session_key].byte_count   += pkt_len
                    if write_flag:
                        self.sessions[session_key].is_write = True
                else:
                    self.sessions[session_key] = Session(
                        src_ip=src_ip, dst_ip=dst_ip,
                        src_port=src_port, dst_port=dst_port,
                        protocol=proto.value,
                        packet_count=1, byte_count=pkt_len,
                        is_write=write_flag,
                    )

            # Protocol stats
            if proto != Protocol.UNKNOWN:
                self.protocol_stats[proto.value] += 1

            # Detailed observation (for write-command tracking)
            if write_flag:
                self.observations.append({
                    "protocol": proto.value,
                    "src_ip": src_ip, "dst_ip": dst_ip,
                    "is_write": True,
                    "function_name": details.get("function_name", details.get("command_name", "")),
                    "details": details,
                })

        except Exception as exc:
            logger.debug(f"Packet parse error: {exc}")

    def _analyze_pcap_scapy(self, path: Path) -> dict:
        """Fallback using scapy if pyshark/tshark is unavailable."""
        try:
            from scapy.all import rdpcap, IP, TCP, UDP, Ether
        except ImportError:
            raise RuntimeError(
                "Neither pyshark nor scapy found.\n"
                "Install one: pip install pyshark  OR  pip install scapy"
            )

        logger.info("Using scapy fallback parser...")
        pkts = rdpcap(str(path))
        for pkt in pkts:
            try:
                if not pkt.haslayer(IP):
                    continue
                src_ip  = pkt[IP].src
                dst_ip  = pkt[IP].dst
                src_mac = pkt[Ether].src if pkt.haslayer(Ether) else ""
                dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else ""

                transport = pkt[TCP] if pkt.haslayer(TCP) else pkt[UDP] if pkt.haslayer(UDP) else None
                if not transport:
                    continue

                src_port = int(transport.sport)
                dst_port = int(transport.dport)
                payload  = bytes(transport.payload)
                pkt_len  = len(pkt)

                proto, details = detect_protocol_from_payload(payload, dst_port, src_port)
                write_flag     = is_write_command(proto, details)

                self._upsert_asset(src_ip, src_mac, proto.value)
                self._upsert_asset(dst_ip, dst_mac, proto.value)

                if proto != Protocol.UNKNOWN:
                    skey = (src_ip, dst_ip, proto.value, dst_port)
                    if skey in self.sessions:
                        self.sessions[skey].packet_count += 1
                        self.sessions[skey].byte_count   += pkt_len
                    else:
                        self.sessions[skey] = Session(
                            src_ip=src_ip, dst_ip=dst_ip,
                            src_port=src_port, dst_port=dst_port,
                            protocol=proto.value,
                            packet_count=1, byte_count=pkt_len,
                            is_write=write_flag,
                        )
                    self.protocol_stats[proto.value] += 1

                if write_flag:
                    self.observations.append({
                        "protocol": proto.value,
                        "src_ip": src_ip, "dst_ip": dst_ip,
                        "is_write": True,
                        "function_name": details.get("function_name", ""),
                        "details": details,
                    })
                self._packet_count += 1
            except Exception as exc:
                logger.debug(f"Scapy parse error: {exc}")

        return self._build_summary()

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    def _upsert_asset(self, ip: str, mac: str, proto: str) -> None:
        if not ip or ip in ("0.0.0.0", "255.255.255.255", ""):
            return
        if ip not in self.assets:
            vi = lookup_oui(mac) if mac else lookup_oui("FF:FF:FF")
            self.assets[ip] = Asset(
                ip=ip, mac=mac, vendor_info=vi,
                in_client_inventory=(ip in self.known_assets),
            )
        asset = self.assets[ip]
        asset.packet_count += 1
        if proto and proto != Protocol.UNKNOWN.value:
            asset.protocols_seen.add(proto)

    def _build_summary(self) -> dict:
        return {
            "total_packets": self._packet_count,
            "assets": [a.to_dict() for a in self.assets.values()],
            "sessions": [s.to_dict() for s in self.sessions.values()],
            "protocol_stats": dict(self.protocol_stats),
            "observations": self.observations,
        }

