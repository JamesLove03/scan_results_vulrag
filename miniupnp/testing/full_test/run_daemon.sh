#!/bin/bash
# run_daemon.sh
# Starts miniupnpd in the foreground for testing.
# Run as root (required for iptables).
#
# Usage:
#   sudo ./run_daemon.sh           # silent corruption build
#   sudo ./run_daemon.sh protected # stack-protected build (crash path)

set -e

TESTING_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$TESTING_DIR/build"
CONF="$TESTING_DIR/miniupnpd_test.conf"

if [ "$1" = "protected" ]; then
    BIN="$BUILD_DIR/miniupnpd_protected"
    echo "[*] Using stack-protected build (expect crash/abort on UDPLITE trigger)"
else
    BIN="$BUILD_DIR/miniupnpd"
    echo "[*] Using unprotected build (expect silent corruption)"
fi

if [ ! -f "$BIN" ]; then
    echo "[-] Binary not found: $BIN"
    echo "    Run ./build_daemon.sh first."
    exit 1
fi

# Create the /etc/upnp directory that tomato_helper() checks
sudo mkdir -p /etc/upnp

echo "[*] Starting miniupnpd (PID will be shown below)..."
echo "[*] HTTP/SOAP listening on 127.0.0.1:5555"
echo "[*] Press Ctrl+C to stop"
echo ""

# Run in foreground with debug output
sudo "$BIN" -f "$CONF" -d
