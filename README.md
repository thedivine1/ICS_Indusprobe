# IndusProbe — OT Passive Scanner & IEC 62443 Analyser

> **100% Passive — Zero packets transmitted to any OT device.**

## What it does

IndusProbe connects to any OT network (via TAP or PCAP file), listens passively, and produces a professional **IEC 62443 Gap Assessment Report** in Markdown/PDF.

### Supported Vendors & Protocols

| Vendor | Protocol | Detection |
|--------|----------|-----------|
| **Siemens** S7-300/400/1200/1500 | S7Comm / S7CommPlus | ✅ |
| **Rockwell** ControlLogix / CompactLogix | EtherNet/IP (CIP) | ✅ |
| **Schneider** M340 / M580 / Quantum | Modbus TCP | ✅ |
| **GE Fanuc** PACSystems RX3i | GE SRTP | ✅ |
| **Yokogawa** CENTUM VP | Vnet/IP + Modbus | ✅ |
| **ABB** AC500 / 800xA | Modbus TCP | ✅ |
| **Honeywell** Experion | OPC-DA / Modbus | ✅ |
| **Emerson** DeltaV | HART / Modbus | ✅ |
| Generic | DNP3, OPC-UA, BACnet, IEC104, MQTT | ✅ |

## Quick Start

```bash
# 1. Install
cd IndusProbe
python -m venv .venv && source .venv/bin/activate
pip install -e .

# 2. Demo mode (no PCAP needed)
indus-probe demo

# 3. Analyse a PCAP file
indus-probe pcap \
  --file /path/to/plant_capture.pcap \
  --client "ABC Manufacturing" \
  --site "Pune Plant, India" \
  --output ./reports

# 4. Live passive capture (48 hours)
indus-probe live \
  --interface eth1 \
  --duration 172800 \
  --client "ABC Manufacturing" \
  --site "Pune Plant, India" \
  --output ./reports
```

## On-Site Usage (The ₹3L Engagement Workflow)

```
1. Arrive at plant
2. Connect TAP between OT switch and SCADA server (30 seconds)
3. Run:  indus-probe live --interface eth1 --duration 172800
4. Leave (laptop captures for 48 hours unattended)
5. Return, unplug TAP
6. Report auto-generated: IndusProbe_ABC_Manufacturing_20261105.pdf
7. Present report → charge ₹3,00,000
```

## IEC 62443 Controls Checked

- SR 1.1 — Human User Authentication
- SR 1.2 — Device Authentication
- SR 1.3 — Account Management
- SR 2.1 — Authorization Enforcement
- SR 3.1 — Communication Integrity (encryption)
- SR 4.1 — Data Confidentiality
- SR 5.1 — Network Segmentation (Zone/Conduit)
- SR 5.2 — Zone Boundary Protection
- SR 6.2 — Continuous Monitoring
- SR 7.1 — DoS Protection

## Safety Guarantee

IndusProbe is architecturally read-only:
- No sockets opened to OT devices
- No ARP, DHCP, ICMP, mDNS, or broadcast generated
- PCAP files only read with `rdpcap()` or pyshark `FileCapture`
- Live capture uses promiscuous mode only — no injection

## Integration with Your Repo Suite

| Repo | IndusProbe Integration |
|------|----------------------|
| `industrial-scanner` | Protocol parsers reused |
| `ICS-Cybersecurity-Audit` | Checklist templates + IEC 62443 controls |
| `ics-iot-ot-hardening` | Remediation recommendations |
| `OT_Security_OnePagers` | Protocol knowledge base |
| `OneAlert` | Forward findings to OneAlert SOC |
| `otforge` | Test IndusProbe against virtual PLC lab |

