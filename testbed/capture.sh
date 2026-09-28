#!/usr/bin/env bash
# IPsecGuard AI — Testbed Capture Script
# Starts strongSwan containers, generates traffic, and captures PCAPs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CAPTURES_DIR="$SCRIPT_DIR/captures"

mkdir -p "$CAPTURES_DIR"

echo "=== IPsecGuard AI Testbed Capture ==="
echo "[1/7] Starting Docker Compose environment..."
docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d

echo "[2/7] Waiting 10 seconds for IPsec tunnels to establish..."
sleep 10

echo "[3/7] Verifying tunnel status..."
docker compose -f "$SCRIPT_DIR/docker-compose.yml" exec vpn-left swanctl --list-sas || true

echo "[4/7] Generating ICMP traffic (ping)..."
docker compose -f "$SCRIPT_DIR/docker-compose.yml" exec vpn-left ping -c 20 172.28.0.3 || true

echo "[5/7] Generating bulk traffic..."
docker compose -f "$SCRIPT_DIR/docker-compose.yml" exec vpn-left \
    dd if=/dev/urandom bs=1024 count=100 2>/dev/null | \
    docker compose -f "$SCRIPT_DIR/docker-compose.yml" exec -T vpn-right cat > /dev/null || true

echo "[6/7] Waiting 5 seconds for final packets..."
sleep 5

echo "[7/7] Stopping containers and collecting captures..."
docker compose -f "$SCRIPT_DIR/docker-compose.yml" stop capture
cp "$CAPTURES_DIR/testbed.pcap" "$PROJECT_DIR/data/testbed_capture.pcap" 2>/dev/null || echo "Warning: capture file not found"
docker compose -f "$SCRIPT_DIR/docker-compose.yml" down

echo ""
echo "=== Capture Complete ==="
echo "PCAP saved to: $PROJECT_DIR/data/testbed_capture.pcap"
echo "Run: make demo  (then upload the PCAP to analyze it)"
