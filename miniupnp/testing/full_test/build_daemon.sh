#!/bin/bash
# build_daemon.sh
# Builds miniupnpd with TOMATO support enabled for full end-to-end testing.
# Run as a regular user from the full_test/ directory on Ubuntu.
#
# Requirements:
#   sudo apt install build-essential libxtables-dev pkg-config

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../../repo/miniupnp/miniupnpd" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"

echo "[*] Script dir: $SCRIPT_DIR"
echo "[*] Repo dir:   $REPO_DIR"
echo "[*] Build dir:  $BUILD_DIR"

if [ ! -f "$REPO_DIR/configure" ]; then
    echo "[-] Cannot find miniupnpd repo at: $REPO_DIR"
    echo "    Check the path and try again."
    exit 1
fi

# Install dependencies
echo "[*] Installing build dependencies..."
sudo apt-get install -y build-essential libxtables-dev pkg-config || {
    echo "[-] apt-get failed — check your internet connection or install manually"
    exit 1
}

mkdir -p "$BUILD_DIR"
cd "$REPO_DIR"

# Run configure to generate config.mk and config.h
echo ""
echo "[*] Running configure..."
./configure --firewall=iptables
if [ ! -f config.mk ]; then
    echo "[-] configure did not produce config.mk — see errors above"
    exit 1
fi
echo "[+] configure succeeded, config.mk generated"

# Inject TOMATO into config.h
echo "[*] Patching config.h to enable TOMATO..."
if grep -q "define TOMATO" config.h 2>/dev/null; then
    echo "[*] TOMATO already defined in config.h, skipping"
else
    printf '\n#ifndef TOMATO\n#define TOMATO\n#endif\n' >> config.h
    echo "[+] TOMATO added to config.h"
fi

# Build unprotected variant — shows silent memory corruption
echo ""
echo "[*] Building miniupnpd (no stack protector)..."
make -f Makefile.linux clean > /dev/null 2>&1 || true
make -f Makefile.linux miniupnpd \
    CPPFLAGS="-DTOMATO" \
    CFLAGS="-g -O0 -fno-stack-protector -Wall -Wno-error" 2>&1
if [ ! -f miniupnpd ]; then
    echo "[-] Build failed — miniupnpd binary not produced. See errors above."
    exit 1
fi
cp miniupnpd "$BUILD_DIR/miniupnpd"
echo "[+] Built: $BUILD_DIR/miniupnpd"

# Build stack-protected variant — shows daemon crash/DoS
echo ""
echo "[*] Building miniupnpd_protected (with stack protector)..."
make -f Makefile.linux clean > /dev/null 2>&1 || true
make -f Makefile.linux miniupnpd \
    CPPFLAGS="-DTOMATO" \
    CFLAGS="-g -O0 -fstack-protector-all -Wall -Wno-error" 2>&1
if [ ! -f miniupnpd ]; then
    echo "[-] Protected build failed. See errors above."
    exit 1
fi
cp miniupnpd "$BUILD_DIR/miniupnpd_protected"
echo "[+] Built: $BUILD_DIR/miniupnpd_protected"

echo ""
echo "[+] All done. Next steps:"
echo "    1. sudo ./run_daemon.sh"
echo "    2. python3 send_soap.py"
echo "    3. sudo ./trigger_save.sh"
