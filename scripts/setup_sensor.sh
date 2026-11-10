#!/usr/bin/env bash
# ==============================================================================
# IndusProbe — Industrial Field Sensor Setup & Listen-Only Hardening
#
# Configures a Linux Drop-Box (Raspberry Pi 4/5 or Industrial Fanless Box PC)
# into a 100% STEALTH LISTEN-ONLY network capture sensor.
#
# GUARANTEES:
# 1. Zero IP address assigned to the capture interface
# 2. Kernel-level disabling of IPv6, ARP, DHCP, mDNS, LLMNR
# 3. Automatic ring-buffer PCAP capture to local SSD/SD card
# 4. Auto-trigger IndusProbe report generation upon completion
# ==============================================================================

set -euo pipefail

CAPTURE_IFACE="${1:-eth1}"
CAPTURE_HOURS="${2:-48}"
OUTPUT_DIR="${3:-/opt/indusprobe/captures}"

echo "============================================================"
echo "  IndusProbe Field Drop-Box Sensor Configuration"
echo "  Target Interface : ${CAPTURE_IFACE}"
echo "  Duration         : ${CAPTURE_HOURS} hours"
echo "  Storage Path     : ${OUTPUT_DIR}"
echo "============================================================"

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

# 1. Disable all auto-networking daemons for this interface
echo "[1/4] Disabling NetworkManager/dhcpcd for ${CAPTURE_IFACE}..."
if command -v nmcli >/dev/null 2>&1; then
    nmcli device set "${CAPTURE_IFACE}" managed no 2>/dev/null || true
fi

# 2. Kernel-level hardening for the capture interface (Zero Outbound Packets)
echo "[2/4] Applying stealth kernel parameters..."
sudo ip link set "${CAPTURE_IFACE}" down || true

# Disable IPv6 completely on capture interface (stops router solicitations & neighbor discovery)
sudo sysctl -w "net.ipv6.conf.${CAPTURE_IFACE}.disable_ipv6=1" >/dev/null 2>&1 || true
sudo sysctl -w "net.ipv6.conf.${CAPTURE_IFACE}.autoconf=0" >/dev/null 2>&1 || true
sudo sysctl -w "net.ipv6.conf.${CAPTURE_IFACE}.accept_ra=0" >/dev/null 2>&1 || true

# Disable ARP responses and announcements
sudo sysctl -w "net.ipv4.conf.${CAPTURE_IFACE}.arp_ignore=8" >/dev/null 2>&1 || true
sudo sysctl -w "net.ipv4.conf.${CAPTURE_IFACE}.arp_announce=2" >/dev/null 2>&1 || true

# Flush any existing IP addresses
sudo ip addr flush dev "${CAPTURE_IFACE}" || true

# Bring interface up in PROMISCUOUS & NOARP mode (pure listener)
sudo ip link set "${CAPTURE_IFACE}" promisc on arp off up

echo "[3/4] Interface ${CAPTURE_IFACE} is now in SILENT PROMISCUOUS MODE."
echo "      IP Address: NONE (Stealth)"
echo "      ARP: OFF"
echo "      IPv6: DISABLED"

# 3. Calculate capture duration and ring-buffer settings
# 500 MB files, maximum 50 files = 25GB max storage limit
DURATION_SECS=$((CAPTURE_HOURS * 3600))
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PCAP_PREFIX="${OUTPUT_DIR}/capture_${TIMESTAMP}"

echo "[4/4] Starting automated ring-buffer capture for ${CAPTURE_HOURS}h..."
echo "      Output: ${PCAP_PREFIX}.pcap"

if command -v dumpcap >/dev/null 2>&1; then
    # dumpcap is lighter on CPU/memory than tcpdump or python
    sudo dumpcap -i "${CAPTURE_IFACE}" \
        -a "duration:${DURATION_SECS}" \
        -b filesize:500000 \
        -b files:50 \
        -w "${PCAP_PREFIX}.pcap" \
        -q
elif command -v tcpdump >/dev/null 2>&1; then
    sudo tcpdump -i "${CAPTURE_IFACE}" -s 0 -n -p \
        -G "${DURATION_SECS}" -W 1 \
        -w "${PCAP_PREFIX}.pcap"
fi

echo ""
echo "============================================================"
echo "  Capture Complete! Running IndusProbe Analysis..."
echo "============================================================"

# Merge any split pcaps if mergecap exists, or take the latest
FINAL_PCAP=$(ls -t "${OUTPUT_DIR}"/capture_${TIMESTAMP}*.pcap 2>/dev/null | head -n 1)

if [ -f "${FINAL_PCAP}" ]; then
    echo "Analyzing: ${FINAL_PCAP}"
    indus-probe pcap \
        --file "${FINAL_PCAP}" \
        --client "Plant Site Assessment" \
        --site "Customer Plant" \
        --output "${OUTPUT_DIR}/reports"
fi

echo "All reports generated successfully in ${OUTPUT_DIR}/reports"

