#!/bin/bash
# build_daemon.sh
# Builds miniupnpd with TOMATO support enabled for full end-to-end testing.
# Run this from the testing/ directory on Ubuntu.
#
# Requirements:
#   sudo apt install build-essential iptables libiptables-dev pkg-config

set -e

REPO_DIR="$(cd "$(dirname "$0")/../repo/miniupnp/miniupnpd" && pwd)"
BUILD_DIR="$(cd "$(dirname "$0")" && pwd)/build"

echo "[*] Repo dir: $REPO_DIR"
echo "[*] Build dir: $BUILD_DIR"

# Install dependencies
echo "[*] Installing dependencies..."
sudo apt-get install -y build-essential iptables libiptables-dev pkg-config 2>/dev/null || true

mkdir -p "$BUILD_DIR"
cd "$REPO_DIR"

# Run configure with iptables firewall
# We manually inject -DTOMATO into CFLAGS since the Tomato OS target
# in configure is designed for the actual Tomato firmware build system.
echo "[*] Running configure..."
./configure --firewall=iptables

# Inject TOMATO and ensure IPPROTO_UDPLITE is available
echo "[*] Patching config.h to enable TOMATO..."
if ! grep -q "define TOMATO" config.h 2>/dev/null; then
    echo "" >> config.h
    echo "#ifndef TOMATO" >> config.h
    echo "#define TOMATO" >> config.h
    echo "#endif" >> config.h
fi

# Build with TOMATO defined and no stack protector so we see
# silent corruption (use CFLAGS_EXTRA=-fstack-protector to test crash path)
echo "[*] Building miniupnpd..."
make -f Makefile.linux \
    CFLAGS="-g -O0 -fno-stack-protector -Wall -DTOMATO" \
    miniupnpd

cp miniupnpd "$BUILD_DIR/miniupnpd"
echo "[+] Built: $BUILD_DIR/miniupnpd"

# Also build a stack-protected version
echo "[*] Building protected variant..."
make -f Makefile.linux \
    CFLAGS="-g -O0 -fstack-protector-all -Wall -DTOMATO" \
    miniupnpd

cp miniupnpd "$BUILD_DIR/miniupnpd_protected"
echo "[+] Built: $BUILD_DIR/miniupnpd_protected"

echo ""
echo "[+] Done. Run ./run_daemon.sh to start the test."
