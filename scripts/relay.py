#!/usr/bin/env python3
"""
Relay: fetches the latest signed price attestation from the TEE oracle
and submits the update_octra_price transaction directly to the Octra RPC.

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
    OCTRA_SEED          12-word mnemonic for signing   (required)
    OCTRA_RPC_URL       Octra RPC endpoint             (default: https://octra.network/rpc)
    RELAY_INTERVAL      Seconds between polls          (default: 120)
    RELAY_LOOP          Set to "1" to run in loop      (default: one-shot)
    RELAY_DRY_RUN       Set to "1" to skip TX submit   (default: off)
"""

import json
import os
import sys
import time
import base64
import hashlib
import hmac
import struct
import urllib.request
import urllib.error
from urllib.parse import urlparse

try:
    from nacl.signing import SigningKey
    from nacl.encoding import RawEncoder
except ImportError:
    print("ERROR: pynacl required. Install with: pip install pynacl", file=sys.stderr)
    sys.exit(1)


ORACLE_URL = os.environ.get("ORACLE_URL", "http://localhost:8080")
SPEC_FILE = os.environ.get("ORACLE_SPEC_FILE", "")
CONTRACT = os.environ.get("OCTUSD_CONTRACT", "")
OCTRA_SEED = os.environ.get("OCTRA_SEED", "")
RPC_URL = os.environ.get("OCTRA_RPC_URL", "https://octra.network/rpc")
INTERVAL = int(os.environ.get("RELAY_INTERVAL", "120"))
LOOP = os.environ.get("RELAY_LOOP", "0") == "1"
DRY_RUN = os.environ.get("RELAY_DRY_RUN", "0") == "1"


def mnemonic_to_seed(mnemonic: str) -> bytes:
    """BIP39 mnemonic to 64-byte seed (PBKDF2-SHA512, 2048 iterations)."""
    return hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), b"mnemonic", 2048)


def derive_hd_seed(master_seed: bytes, index: int = 0) -> bytes:
    """Octra HD derivation v2: HMAC-SHA512 with key 'Octra seed', take first 32 bytes."""
    if index == 0:
        mac = hmac.new(b"Octra seed", master_seed, hashlib.sha512).digest()
        return mac[:32]
    else:
        data = master_seed + struct.pack("<I", index)
        mac = hmac.new(b"Octra seed", data, hashlib.sha512).digest()
        return mac[:32]


def derive_signing_key(mnemonic: str) -> tuple:
    """Derive ed25519 signing key from mnemonic. Returns (SigningKey, address, pub_b64)."""
    master = mnemonic_to_seed(mnemonic)
    seed_32 = derive_hd_seed(master, 0)
    sk = SigningKey(seed_32)
    pk_bytes = sk.verify_key.encode()
    addr = derive_address(pk_bytes)
    pub_b64 = base64.b64encode(pk_bytes).decode()
    return sk, addr, pub_b64


def derive_address(pubkey: bytes) -> str:
    """Derive Octra address: 'oct' + base58(sha256(pubkey)) padded to 44 chars."""
    h = hashlib.sha256(pubkey).digest()
    b58 = base58_encode(h)
    while len(b58) < 44:
        b58 = "1" + b58
    return "oct" + b58


def base58_encode(data: bytes) -> str:
    """Base58 encode (Bitcoin alphabet)."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(data, "big")
    result = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(alphabet[r])
    # leading zeros
    for b in data:
        if b == 0:
            result.append(alphabet[0])
        else:
            break
    return "".join(reversed(result))


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


def rpc_call(method, params=None):
    """Call Octra RPC."""
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1,
        "method": method,
        "params": params or []
    }).encode()
    req = urllib.request.Request(
        RPC_URL, data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    if "error" in data:
        raise Exception(f"RPC error: {data['error']}")
    return data["result"]


def get_nonce(address: str) -> int:
    """Get current nonce for address."""
    result = rpc_call("octra_balance", [address])
    return result.get("pending_nonce", result.get("nonce", 0))


def canonical_json(tx: dict) -> str:
    """Build canonical JSON for signing (matches C++ canonical_json exactly)."""
    def esc(s):
        return s.replace("\\", "\\\\").replace('"', '\\"')

    s = '{"from":"' + esc(tx["from"]) + '"'
    s += ',"to_":"' + esc(tx["to_"]) + '"'
    s += ',"amount":"' + esc(tx["amount"]) + '"'
    s += ',"nonce":' + str(tx["nonce"])
    s += ',"ou":"' + esc(tx["ou"]) + '"'
    s += ',"timestamp":' + json.dumps(tx["timestamp"])
    s += ',"op_type":"' + esc(tx["op_type"]) + '"'
    if tx.get("encrypted_data"):
        s += ',"encrypted_data":"' + esc(tx["encrypted_data"]) + '"'
    if tx.get("message"):
        s += ',"message":"' + esc(tx["message"]) + '"'
    s += '}'
    return s


def sign_and_submit(sk, from_addr, pub_b64, price_int, timestamp, signature):
    """Build, sign, and submit the update_octra_price transaction."""
    nonce = get_nonce(from_addr)
    params_json = json.dumps([price_int, timestamp, signature])

    tx = {
        "from": from_addr,
        "to_": CONTRACT,
        "amount": "0",
        "nonce": nonce + 1,
        "ou": "1000",
        "timestamp": time.time(),
        "op_type": "call",
        "encrypted_data": "update_octra_price",
        "message": params_json,
    }

    msg = canonical_json(tx)
    sig = sk.sign(msg.encode(), encoder=RawEncoder)
    tx_sig = base64.b64encode(sig.signature).decode()

    submit_payload = {
        "from": tx["from"],
        "to_": tx["to_"],
        "amount": tx["amount"],
        "nonce": tx["nonce"],
        "ou": tx["ou"],
        "timestamp": tx["timestamp"],
        "signature": tx_sig,
        "public_key": pub_b64,
        "op_type": tx["op_type"],
        "encrypted_data": tx["encrypted_data"],
        "message": tx["message"],
    }

    result = rpc_call("octra_submit", [submit_payload])
    return result


def relay_once(spec, sk, from_addr, pub_b64):
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

    result = sign_and_submit(sk, from_addr, pub_b64, price_int, timestamp, signature)
    print(f"  TX result: {json.dumps(result)}")
    print()


def main():
    if not SPEC_FILE:
        print("ERROR: ORACLE_SPEC_FILE not set", file=sys.stderr)
        sys.exit(1)
    if not CONTRACT:
        print("ERROR: OCTUSD_CONTRACT not set", file=sys.stderr)
        sys.exit(1)
    if not OCTRA_SEED:
        print("ERROR: OCTRA_SEED not set", file=sys.stderr)
        sys.exit(1)

    # Derive signing key from mnemonic
    sk, from_addr, pub_b64 = derive_signing_key(OCTRA_SEED)
    print(f"Wallet:   {from_addr}")

    spec = load_spec()
    print(f"Oracle:   {ORACLE_URL}")
    print(f"Contract: {CONTRACT}")
    print(f"RPC:      {RPC_URL}")
    print(f"Spec:     {SPEC_FILE}")
    print(f"Mode:     {'loop' if LOOP else 'one-shot'}{' (dry-run)' if DRY_RUN else ''}")
    print()

    while True:
        try:
            relay_once(spec, sk, from_addr, pub_b64)
        except urllib.error.URLError as e:
            print(f"ERROR: network error: {e}", file=sys.stderr)
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)

        if not LOOP:
            break
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()


if __name__ == "__main__":
    main()
