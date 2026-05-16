#!/usr/bin/env python3
"""
Relay: fetches the latest signed price attestation from the TEE oracle
and submits the update_octra_price transaction via the Octra webcli.

Usage:
    # One-shot: fetch attestation and submit TX
    python3 relay.py

    # Loop mode: poll and submit every RELAY_INTERVAL seconds
    RELAY_LOOP=1 python3 relay.py

    # Dry-run: print what would be submitted without posting
    RELAY_DRY_RUN=1 python3 relay.py

Environment:
    ORACLE_URL          TEE oracle HTTP endpoint       (default: http://localhost:8080)
    ORACLE_SPEC_FILE    Path to query spec JSON file   (required)
    OCTUSD_CONTRACT     Deployed OctUSD address        (required)
    WEBCLI_URL          Webcli HTTP endpoint           (default: http://localhost:8420)
    RELAY_INTERVAL      Seconds between polls          (default: 120)
    RELAY_LOOP          Set to "1" to run in loop      (default: one-shot)
    RELAY_DRY_RUN       Set to "1" to skip TX submit   (default: off)
"""

import json
import os
import sys
import time
import http.client
import urllib.request
import urllib.error
from urllib.parse import urlparse


ORACLE_URL = os.environ.get("ORACLE_URL", "http://localhost:8080")
SPEC_FILE = os.environ.get("ORACLE_SPEC_FILE", "")
CONTRACT = os.environ.get("OCTUSD_CONTRACT", "")
WEBCLI_URL = os.environ.get("WEBCLI_URL", "http://localhost:8420")
INTERVAL = int(os.environ.get("RELAY_INTERVAL", "120"))
LOOP = os.environ.get("RELAY_LOOP", "0") == "1"
DRY_RUN = os.environ.get("RELAY_DRY_RUN", "0") == "1"


def load_spec():
    """Load the oracle query spec from the JSON file."""
    with open(SPEC_FILE, "r") as f:
        return json.load(f)


def fetch_attestation(spec):
    """POST the query spec to the oracle and return the attestation."""
    import socket
    body = json.dumps(spec).encode()
    parsed = urlparse(ORACLE_URL)
    host = parsed.hostname
    port = parsed.port or 80
    raw = (
        f"POST /latest HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + body
    sock = socket.create_connection((host, port), timeout=30)
    sock.sendall(raw)
    resp = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        resp += chunk
    sock.close()
    parts = resp.split(b"\r\n\r\n", 1)
    if len(parts) < 2:
        raise Exception(f"malformed response: {resp[:200].decode()}")
    status_line = parts[0].split(b"\r\n")[0].decode()
    if "200" not in status_line:
        raise Exception(f"oracle returned {status_line}: {parts[1].decode()}")
    return json.loads(parts[1])


def submit_price_update(price_int, timestamp, signature):
    """Submit update_octra_price TX via webcli."""
    payload = {
        "address": CONTRACT,
        "method": "update_octra_price",
        "params": [price_int, timestamp, signature],
        "ou": "1000",
        "amount": "0",
    }
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{WEBCLI_URL}/api/contract/call",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def relay_once(spec):
    att = fetch_attestation(spec)

    price_int = int(att["value"])
    timestamp = att["timestamp"]
    signature = att["signature"]

    print("─" * 60)
    print(f"  Value (raw):     {att['value']}")
    print(f"  Price (int):     {price_int}")
    print(f"  Timestamp:       {timestamp}")
    print(f"  Sources:         {att['sources_used']}/{att['sources_total']}")
    print(f"  Spec hash:       {att['spec_hash']}")
    print(f"  Public key:      {att['public_key']}")
    print(f"  Signature:       {signature}")
    print()
    print(f"  Contract call:   update_octra_price({price_int}, {timestamp}, \"{signature}\")")
    print()

    if DRY_RUN:
        print("  [DRY RUN] Skipping TX submission")
        return

    result = submit_price_update(price_int, timestamp, signature)
    print(f"  TX result: {json.dumps(result)}")
    print()


def main():
    if not SPEC_FILE:
        print("ERROR: ORACLE_SPEC_FILE not set", file=sys.stderr)
        sys.exit(1)
    if not CONTRACT:
        print("ERROR: OCTUSD_CONTRACT not set", file=sys.stderr)
        sys.exit(1)

    spec = load_spec()
    print(f"Oracle:   {ORACLE_URL}")
    print(f"Contract: {CONTRACT}")
    print(f"Webcli:   {WEBCLI_URL}")
    print(f"Spec:     {SPEC_FILE}")
    print(f"Mode:     {'loop' if LOOP else 'one-shot'}{' (dry-run)' if DRY_RUN else ''}")
    print()

    while True:
        try:
            relay_once(spec)
        except urllib.error.URLError as e:
            print(f"ERROR: network error: {e}", file=sys.stderr)
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)

        if not LOOP:
            break
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
