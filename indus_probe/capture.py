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
    observed_vendor: str | None = None
    observed_model: str | None = None
    observed_firmware: str | None = None
    identity_evidence: str = "OUI_INFERENCE"  # CIP_IDENTITY, MODBUS_DEVICE_ID, UMAS_DECODE, OUI_INFERENCE
    confidence: str = "MEDIUM"                # HIGH, MEDIUM, LOW

    def record_observed_identity(
        self,
        vendor: str,
        model: str = "",
        evidence: str = "PROTOCOL_INSPECTION",
        firmware: str = "",
    ) -> None:
        if vendor and evidence in ("CIP_IDENTITY", "MODBUS_DEVICE_ID", "UMAS_DECODE"):
            self.observed_vendor = vendor
            if model:
                self.observed_model = model
            if firmware:
                self.observed_firmware = firmware
            self.identity_evidence = evidence
            self.confidence = "HIGH"

    def to_dict(self) -> dict:
        effective_vendor = self.observed_vendor or (self.vendor_info.vendor if self.vendor_info else "Unknown")
        effective_model = self.observed_model or (self.vendor_info.device_hint if self.vendor_info else "")
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": effective_vendor,
            "observed_vendor": self.observed_vendor or "",
            "observed_model": effective_model,
            "observed_firmware": self.observed_firmware or "",
            "identity_evidence": self.identity_evidence,
            "confidence": self.confidence,
            "device_hint": self.vendor_info.device_hint if self.vendor_info else "",
            "purdue_level": self.vendor_info.purdue_level if self.vendor_info else self.purdue_level,
            "protocols_seen": list(self.protocols_seen),
            "protocol_expected": self.vendor_info.protocol_expected if self.vendor_info else "",
            "packet_count": self.packet_count,
            "is_ot_device": self.vendor_info.is_ot_device if self.vendor_info else False,
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
    read_count: int = 0
    write_count: int = 0
    undecoded_count: int = 0
    unsupported_count: int = 0
    is_write: bool = False

    @property
    def classification(self) -> str:
        if self.write_count > 0:
            return "WRITE_OR_CONTROL"
        elif self.read_count > 0:
            return "READ_ONLY"
        elif self.unsupported_count > 0:
            return "UNSUPPORTED_OPERATION"
        elif self.undecoded_count > 0:
            return "UNDECODED_PAYLOAD"
        return "HEADER_ONLY"

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "read_count": self.read_count,
            "write_count": self.write_count,
            "undecoded_count": self.undecoded_count,
            "unsupported_count": self.unsupported_count,
            "is_write": self.is_write,
            "classification": self.classification,
        }


class PcapAnalyzer:
    """
    Passive PCAP/live-capture analyzer.
    Requires pyshark (tshark) or scapy for packet parsing.
    """

    def __init__(self, known_assets: list[str] | None = None):
        self.assets: dict[str, Asset] = {}
        self.sessions: dict[tuple, Session] = {}
        self.observations: list[dict] = []
        self.protocol_stats: dict[str, int] = defaultdict(int)
        self.known_assets = set(known_assets or [])
        self._packet_count = 0

    def _reset_state(self) -> None:
        """Reset internal accumulator state to prevent duplicate data across parsing passes."""
        self.assets.clear()
        self.sessions.clear()
        self.observations.clear()
        self.protocol_stats.clear()
        self._packet_count = 0

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def analyze_pcap(self, pcap_path: str | Path) -> dict:
        """Analyze a PCAP/PCAPNG file. Returns summary dict."""
        path = Path(pcap_path)
        if not path.exists():
            raise FileNotFoundError(f"PCAP not found: {path}")

        self._reset_state()
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
            logger.warning(f"pyshark/tshark error ({e}) — resetting state and falling back to scapy engine")
            self._reset_state()
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

        self._reset_state()
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

            # Genuine application-layer payload extraction from transport layer
            payload = b""
            payload_hex = getattr(transport, "payload", None) or getattr(transport, "segment_data", None)
            if payload_hex:
                try:
                    cleaned_hex = str(payload_hex).replace(":", "").replace(" ", "").strip()
                    payload = bytes.fromhex(cleaned_hex)
                except (ValueError, TypeError):
                    payload = b""

            # Protocol detection
            proto, details = detect_protocol_from_payload(payload, dst_port, src_port)
            write_flag = is_write_command(proto, details)

            # Update assets
            if src_ip and src_mac:
                self._upsert_asset(src_ip, src_mac, proto.value, details)
            if dst_ip and dst_mac:
                self._upsert_asset(dst_ip, dst_mac, proto.value, details)

            # Update sessions
            if src_ip and dst_ip and proto != Protocol.UNKNOWN:
                self._update_session(src_ip, dst_ip, src_port, dst_port, proto, pkt_len, details)
                self.protocol_stats[proto.value] += 1

            # Detailed observation (for write-command tracking)
            if write_flag is True:
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
            import logging
            logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
            from scapy.layers.l2 import Ether
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.utils import rdpcap
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
                # Genuine transport payload: bytes of transport layer's payload
                payload  = bytes(transport.payload) if transport.payload else b""
                pkt_len  = len(pkt)

                proto, details = detect_protocol_from_payload(payload, dst_port, src_port)
                write_flag     = is_write_command(proto, details)

                self._upsert_asset(src_ip, src_mac, proto.value, details)
                self._upsert_asset(dst_ip, dst_mac, proto.value, details)

                if proto != Protocol.UNKNOWN:
                    self._update_session(src_ip, dst_ip, src_port, dst_port, proto, pkt_len, details)
                    self.protocol_stats[proto.value] += 1

                if write_flag is True:
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

    def _update_session(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        proto: Protocol,
        pkt_len: int,
        details: dict,
    ) -> None:
        """Update or insert session with rigorous read/write/undecoded semantics."""
        session_key = (src_ip, dst_ip, proto.value, dst_port)
        write_flag = is_write_command(proto, details)
        op_type = details.get("operation_type", "UNDECODED")

        if session_key in self.sessions:
            session = self.sessions[session_key]
            session.packet_count += 1
            session.byte_count += pkt_len
        else:
            session = Session(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                protocol=proto.value,
                packet_count=1, byte_count=pkt_len,
                is_write=False,
            )
            self.sessions[session_key] = session

        # Increment specific operation counters
        if write_flag is True or op_type == "WRITE":
            session.write_count += 1
            session.is_write = True  # Persistent write flag once any write is seen
        elif op_type in ("READ", "SESSION_MGMT"):
            session.read_count += 1
        elif op_type == "UNSUPPORTED":
            session.unsupported_count += 1
        else:
            session.undecoded_count += 1

    def _upsert_asset(self, ip: str, mac: str, proto: str, details: dict | None = None) -> None:
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

        # Record protocol-derived identity evidence if present
        if details and details.get("observed_vendor"):
            asset.record_observed_identity(
                vendor=details["observed_vendor"],
                model=details.get("observed_model", ""),
                evidence=details.get("vendor_evidence", "PROTOCOL_INSPECTION"),
                firmware=details.get("observed_firmware", ""),
            )

    def _build_summary(self) -> dict:
        return {
            "total_packets": self._packet_count,
            "assets": [a.to_dict() for a in self.assets.values()],
            "sessions": [s.to_dict() for s in self.sessions.values()],
            "protocol_stats": dict(self.protocol_stats),
            "observations": self.observations,
        }
