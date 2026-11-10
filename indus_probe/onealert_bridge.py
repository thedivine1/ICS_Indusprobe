"""
IndusProbe — OneAlert SOC Bridge

Exports IndusProbe passive findings, detected assets, and protocol events
into OneAlert / Suricata EVE compatible JSON formats, enabling direct ingestion
into the OneAlert AI Security OS platform.
"""

from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def export_to_onealert(
    assets: list[dict[str, Any]],
    sessions: list[dict[str, Any]],
    findings: list[Any],
    output_dir: Path,
) -> dict[str, Path]:
    """
    Export IndusProbe data to OneAlert:
      1. onealert_eve_events.jsonl: Suricata EVE format for OneAlert Detect/Triage agents
      2. onealert_assets.json: Asset inventory format for OneAlert asset tracking
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    eve_path = output_dir / "onealert_eve_events.jsonl"
    assets_path = output_dir / "onealert_assets.json"

    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. Generate EVE events from sessions and findings
    eve_records: list[dict[str, Any]] = []

    # Map findings to EVE alerts
    severity_map = {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 3,
        "LOW": 4,
        "INFO": 5,
    }

    for f in findings:
        sr_id = getattr(f, "sr_id", "SR-UNKNOWN")
        title = getattr(f, "finding", "OT Security Finding")
        sev = getattr(f, "severity", "MEDIUM")
        evidence = getattr(f, "evidence", "")
        mitre = getattr(f, "mitre_ref", "")

        record = {
            "timestamp": now_iso,
            "event_type": "alert",
            "src_ip": "0.0.0.0",
            "dest_ip": "0.0.0.0",
            "proto": "TCP",
            "alert": {
                "signature": f"[{sr_id}] {title}",
                "signature_id": 900000 + abs(hash(sr_id)) % 100000,
                "severity": severity_map.get(sev, 3),
                "category": f"IEC 62443 {sr_id}",
                "action": "allowed",
                "metadata": {
                    "evidence": evidence,
                    "mitre_ics": mitre,
                    "engine": "IndusProbe",
                },
            },
        }
        eve_records.append(record)

    # Map write sessions to OT events
    for s in sessions:
        if s.get("is_write"):
            record = {
                "timestamp": now_iso,
                "event_type": "alert",
                "src_ip": s.get("src_ip", "127.0.0.1"),
                "src_port": s.get("src_port", 0),
                "dest_ip": s.get("dst_ip", "127.0.0.1"),
                "dest_port": s.get("dst_port", 0),
                "proto": "TCP",
                "alert": {
                    "signature": f"IndusProbe OT Write Operation: {s.get('protocol')}",
                    "signature_id": 900100,
                    "severity": 2,
                    "category": "Industrial Protocol Command Write",
                    "action": "observed",
                    "metadata": {
                        "protocol": s.get("protocol"),
                        "packet_count": s.get("packet_count"),
                        "engine": "IndusProbe",
                    },
                },
            }
            eve_records.append(record)

    with open(eve_path, "w", encoding="utf-8") as f:
        for r in eve_records:
            f.write(json.dumps(r) + "\n")

    # 2. Generate OneAlert Asset list
    formatted_assets = []
    for a in assets:
        purdue = a.get("purdue_level", "Unknown")
        lvl = 1
        if "Level 2" in purdue:
            lvl = 2
        elif "Level 3" in purdue:
            lvl = 3
        elif "Level 0" in purdue:
            lvl = 0

        formatted_assets.append({
            "ip_address": a.get("ip"),
            "mac_address": a.get("mac"),
            "name": f"{a.get('vendor')} {a.get('device_hint')}",
            "vendor": a.get("vendor"),
            "device_type": a.get("device_hint"),
            "purdue_level": lvl,
            "protocols": a.get("protocols_seen", []),
            "in_inventory": a.get("in_client_inventory", True),
            "source": "IndusProbe Passive Scan",
            "first_seen": now_iso,
            "last_seen": now_iso,
        })

    with open(assets_path, "w", encoding="utf-8") as f:
        json.dump(formatted_assets, f, indent=2)

    return {"eve_jsonl": eve_path, "assets_json": assets_path}

