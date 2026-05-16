#!/usr/bin/env python3
"""Deploy OctUSD contract via the Octra webcli local API."""

import json
import os
import sys
import time
import requests

WEBCLI = os.environ.get("WEBCLI_URL", "http://127.0.0.1:8420")
SEED = os.environ.get("OCTRA_SEED", "")
PIN = os.environ.get("OCTRA_PIN", "")
RPC_URL = os.environ.get("OCTRA_RPC_URL", "http://46.101.86.250:8080")

ORACLE_PUBKEY = "5egzVAmCibqiul2WLfxQSuTiM3o4rdxyCLngk3DMc2g="  # base64 (Octra uses b64 for ed25519)
ORACLE_DOMAIN = "octusd-price-v1"
ORACLE_SPEC_HASH = ""  # will be computed from the oracle's /spec endpoint or hardcoded after first deploy
INITIAL_PRICE = 40151  # ~$0.0402

def api(method, path, **kwargs):
    fn = getattr(requests, method)
    r = fn(f"{WEBCLI}{path}", **kwargs, timeout=30)
    data = r.json()
    if "error" in data:
        print(f"ERROR {path}: {data['error']}")
        sys.exit(1)
    return data

def rpc(method_name, params=None):
    r = requests.post(f"{RPC_URL}/rpc", json={
        "jsonrpc": "2.0", "id": 1,
        "method": method_name,
        "params": params or []
    }, timeout=30)
    data = r.json()
    if "error" in data:
        print(f"RPC ERROR {method_name}: {data['error']}")
        sys.exit(1)
    return data["result"]

def main():
    if not SEED:
        print("ERROR: OCTRA_SEED not set", file=sys.stderr)
        sys.exit(1)
    if not PIN:
        print("ERROR: OCTRA_PIN not set", file=sys.stderr)
        sys.exit(1)

    # 1. Check wallet status
    status = api("get", "/api/wallet/status")
    print(f"Wallet status: loaded={status.get('loaded')}")

    if not status.get("loaded"):
        print("Importing wallet with seed phrase...")
        result = api("post", "/api/wallet/import", json={
            "mnemonic": SEED,
            "pin": PIN,
            "name": "octusd-deployer",
        })
        print(f"Wallet imported: {result.get('address')}")
    else:
        wallet = api("get", "/api/wallet")
        print(f"Wallet already loaded: {wallet.get('address')}")

    # 2. Set RPC URL
    wallet = api("get", "/api/wallet")
    if wallet.get("rpc_url") != RPC_URL:
        print(f"Setting RPC URL to {RPC_URL}...")
        api("post", "/api/settings", json={
            "rpc_url": RPC_URL,
            "explorer_url": wallet.get("explorer_url", "https://octrascan.io"),
        })

    # 3. Check balance
    balance = api("get", "/api/balance")
    bal_raw = int(balance.get("public_balance", "0"))
    bal_oct = bal_raw / 1_000_000
    print(f"Balance: {bal_oct:.6f} OCT ({bal_raw} raw)")
    if bal_raw == 0:
        print("\nWARNING: Wallet has zero balance!")
        print(f"Send OCT to: {wallet.get('address')}")
        print("Then run this script again.")
        sys.exit(1)

    # 4. Read source and prepare for single-file compile
    with open("main.aml") as f:
        src = f.read()
    # Strip import and implements for single-file compile
    src = src.replace('import IOCS01 from "interfaces/IOCS01.aml"\n\n', '')
    src = src.replace(' implements IOCS01', '')

    # 5. Compile via RPC (single-file compiler works, multi-file stubs)
    print("Compiling contract...")
    compile_result = rpc("octra_compileAml", [src])
    bytecode = compile_result.get("bytecode", "")
    abi = json.loads(compile_result.get("abi", "{}"))
    print(f"Compiled: {compile_result.get('instructions')} instructions, "
          f"{compile_result.get('size')} bytes, "
          f"{len(abi.get('functions', []))} functions")
    if not bytecode:
        print("ERROR: no bytecode produced")
        sys.exit(1)

    # 6. Preview address
    addr_result = api("post", "/api/contract/address", json={
        "bytecode": bytecode,
    })
    print(f"Predicted contract address: {addr_result.get('address')}")

    # 7. Deploy with constructor params
    params = json.dumps([ORACLE_PUBKEY, ORACLE_DOMAIN, ORACLE_SPEC_HASH, INITIAL_PRICE])
    print(f"Deploying with params: {params}")

    # Get recommended fee
    fee_result = rpc("octra_recommendedFee", ["deploy"])
    ou = fee_result.get("recommended", "200000")
    print(f"Using fee: {ou} ou")

    deploy_result = api("post", "/api/contract/deploy", json={
        "bytecode": bytecode,
        "params": params,
        "ou": ou,
    })
    print(f"Deploy TX hash: {deploy_result.get('tx_hash')}")
    print(f"Contract address: {deploy_result.get('contract_address')}")

    # 8. Wait for confirmation
    tx_hash = deploy_result.get("tx_hash")
    if tx_hash:
        print("Waiting for confirmation...")
        for i in range(30):
            time.sleep(2)
            try:
                tx = api("get", f"/api/tx?hash={tx_hash}")
                status = tx.get("status", "pending")
                print(f"  [{i*2}s] Status: {status}")
                if status == "confirmed":
                    print(f"\nContract deployed successfully!")
                    print(f"  Address: {deploy_result.get('contract_address')}")
                    print(f"  TX Hash: {tx_hash}")

                    # 9. Verify with a read call
                    view = api("get", f"/api/contract/view?address={deploy_result['contract_address']}&method=get_name&params=[]")
                    print(f"  get_name() = {view.get('result')}")
                    return
                elif status == "rejected":
                    print(f"\nDeploy REJECTED: {tx.get('reject_reason')}")
                    return
            except Exception as e:
                print(f"  [{i*2}s] Checking... ({e})")
        print("Timed out waiting for confirmation")

if __name__ == "__main__":
    main()
