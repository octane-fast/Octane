---
name: oyster-tee-oracle
description: 'Deploy, manage, and interact with Marlin Oyster CVM TEE enclaves for oracle price feeds. Use when deploying to Oyster, fetching TEE-attested prices, managing enclave jobs, or relaying signed attestations to on-chain contracts.'
---

# Marlin Oyster TEE Oracle

## Overview

Deploy containerized oracle services inside Marlin Oyster TEE enclaves. The KMS inside the enclave derives deterministic ed25519 keys, ensuring the same image always produces the same public key.

## Prerequisites

- `oyster-cvm` CLI installed at `/usr/local/bin/oyster-cvm`
- Arbitrum wallet with USDC for enclave payments
- Docker image pushed to a public registry

## Key Derivation

The enclave KMS derives keys at: `http://127.0.0.1:1100/derive/ed25519?path=<derivation-path>`

To predict the public key for a given image:
```bash
oyster-cvm kms-derive --image-id <IMAGE_ID> --path <PATH> --key-type ed25519/public
```

Image ID is computed from the docker-compose digest + PCR preset.

## Deployment

```bash
oyster-cvm deploy \
  --wallet-private-key <HEX_PRIVATE_KEY> \
  --docker-compose ./docker-compose.yml \
  --duration-in-minutes 30 \
  --region us-east-1 \
  --arch amd64
```

### Key Parameters
- `--duration-in-minutes`: How long to fund the enclave
- `--region`: AWS region (us-east-1, ap-south-1, etc.)
- `--arch`: amd64 or arm64
- Cost: ~0.18 USDC/hour typical

### Deploy Output
- Job ID: `0x000...XXXX`
- IP address: printed after ~3 min boot wait
- The deploy command blocks for 3+ minutes waiting for the enclave to become reachable

## Management

### List Jobs
```bash
oyster-cvm list --address <ETH_ADDRESS>
```

### Stop Job
```bash
oyster-cvm stop --wallet-private-key <KEY> --job-id <JOB_ID>
```

**WARNING**: `oyster-cvm stop` is unreliable. It first calls `jobReviseRateInitiate` to set rate to 0, then waits 5 minutes, then calls `jobReviseRateFinalize` + `jobClose`. This often fails with "execution reverted" if:
- The job is already in a rate-revision state
- Another stop attempt is in-flight
- The job is near expiry

**Preferred approach**: Use `cast send` to call `jobClose` directly (see Force-Kill section below). This is faster and more reliable.

### Stream Logs
```bash
oyster-cvm logs --ip <INSTANCE_IP>
```

## Oracle Price Feed Pattern

### Docker Compose
```yaml
services:
  oracle:
    image: username/oracle-image:latest
    network_mode: host
    restart: unless-stopped
    environment:
      - PORT=8080
```

### Fetching Attestation

The oracle expects a POST with sources/aggregation config:

```bash
curl -X POST http://<INSTANCE_IP>:8080/latest \
  -H "Content-Type: application/json" \
  -d @spec.json
```

**Note**: The oracle's TCP server reads the entire request in a single `read()` call (8192 byte buffer). Python's `urllib` sends headers and body in separate TCP segments, which causes 400 errors. Use raw sockets or `requests` library instead:

```python
import socket, json

def fetch_attestation(oracle_url, spec):
    host, port = oracle_url.replace("http://", "").split(":")
    body = json.dumps(spec).encode()
    request = (
        f"POST /latest HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body
    sock = socket.create_connection((host, int(port)), timeout=15)
    sock.sendall(request)  # single sendall ensures headers+body in one segment
    # ... read response
```

Returns:
```json
{
  "value": 41499,
  "timestamp": 1778877231,
  "domain": "octusd-price-v1",
  "spec_hash": "29c6e50f...",
  "message": "octusd-price-v1:29c6e50f...:41499:1778877231",
  "signature": "<base64 ed25519 signature>",
  "public_key": "<base64 ed25519 public key>",
  "sources_used": 3,
  "sources_total": 3
}
```

When `scale` is set in the request (e.g. `"scale": 1000000`), the value is `raw_float * scale` truncated to integer. The signed message uses this integer string, matching the contract's `to_string(new_price)`.

### Relaying to Octra Contract

The relay script (`scripts/relay.py`) signs and submits transactions directly to the Octra RPC — no webcli needed.

**Required env vars:**
```bash
OCTRA_SEED="<12-word mnemonic>"
ORACLE_URL=http://<ENCLAVE_IP>:8080
ORACLE_SPEC_FILE=oracle/spec.json
OCTUSD_CONTRACT=oct2hJMZbBdAAKTBXK61vs1TUx8oQNZVZyEpR4SXGFXgtvE
OCTRA_RPC_URL=https://octra.network/rpc   # optional, this is the default
```

**Run:**
```bash
# One-shot
OCTRA_SEED="..." ORACLE_URL=http://<IP>:8080 ORACLE_SPEC_FILE=oracle/spec.json \
  OCTUSD_CONTRACT=oct2hJMZbBdAAKTBXK61vs1TUx8oQNZVZyEpR4SXGFXgtvE python3 scripts/relay.py

# Loop mode (every 2 min)
RELAY_LOOP=1 OCTRA_SEED="..." ORACLE_URL=http://<IP>:8080 \
  ORACLE_SPEC_FILE=oracle/spec.json \
  OCTUSD_CONTRACT=oct2hJMZbBdAAKTBXK61vs1TUx8oQNZVZyEpR4SXGFXgtvE python3 scripts/relay.py
```

**How it works:**
1. Derives ed25519 keypair from mnemonic (BIP39 → PBKDF2-SHA512 → HMAC-SHA512 with "Octra seed" key → ed25519 seed)
2. Fetches signed attestation from TEE oracle (raw socket POST to avoid split TCP segments)
3. Gets current nonce from `octra_balance` RPC
4. Builds canonical JSON transaction (`op_type: "call"`, `encrypted_data: "update_octra_price"`, `message: [price, timestamp, sig]`)
5. Signs with ed25519 and submits via `octra_submit` RPC

**Note:** The oracle returns signatures already in base64 format — no hex→base64 conversion needed.

## Current Deployment Info

- Arbitrum wallet address: `0x9894d145331254a78666866159c5e16D307f1006`
- Octra wallet address: `octEfXCJva6oTHpvZYf3i2MypeJ2BwHcbe2ziVhnTaWpi9J`
- OctUSD contract address: `oct2hJMZbBdAAKTBXK61vs1TUx8oQNZVZyEpR4SXGFXgtvE`
- Octra RPC: `https://octra.network/rpc`
- Oracle image: `ghcr.io/octane-defi/octusd-oracle:latest`
- GHCR image (pinned): `ghcr.io/octane-defi/octusd-oracle:sha-4882472`
- Oracle pubkey (hex): `08791f07b4e40129697f3bd274d02b5db6b19b667fb8e5da86b0e17a72fbaf3e`
- Oracle pubkey (b64): `CHkfB7TkASlpfzvSdNArXbaxm2Z/uOXahrDhenL7rz4=`
- KMS derive path: `oracle-price-feed`
- Image ID: `1a6de70ab2fe6b0e4a7a4233f1cd081c68b8b68a9242408efcf78c536145dc90`
- Marketplace contract: `0x9d95D61eA056721E358BC49fE995caBF3B86A34B`
- GitHub repo: `octane-defi/octUSD` (account: `chief-of-gas`)

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Deploy blocks forever | The 3-min wait is normal; kill terminal and check `list` |
| Stop fails with "reverted" | Use `cast` to call `jobClose` directly (see below) |
| Old IP unreachable | Instance was recycled; deploy a new one |
| Signature invalid on-chain | Convert hex → base64 before submitting |

### Force-Kill a Stuck Job

When `oyster-cvm stop` reverts or hangs, call `jobClose` directly on the Arbitrum marketplace contract:

```bash
# Load private key from .env
source .env
cast send 0x9d95D61eA056721E358BC49fE995caBF3B86A34B \
  "jobClose(bytes32)" \
  0x000000000000000000000000000000000000000000000000000000000000XXXX \
  --private-key "0x${ARBITRUM_PRIVATE_KEY}" \
  --rpc-url https://arb1.arbitrum.io/rpc
```

This bypasses the rate-revise step and terminates the job immediately, refunding remaining USDC.

**Important**: The job ID must be zero-padded to 32 bytes (64 hex chars). If your job ID is `0x3023`, pad it as:
`0x0000000000000000000000000000000000000000000000000000000000003023`

You can verify the job is closed by running `oyster-cvm list` — it should no longer appear, or show a zero balance.

### Full Redeployment Checklist

When updating the oracle image (e.g. after code changes):

1. **Close old job**: `cast send` → `jobClose` (see above)
2. **Push code**: `git push` → CI builds new Docker image
3. **Update docker-compose.yml** with new image tag (e.g. `sha-XXXXXXX`)
4. **Compute new image ID**: `oyster-cvm compute-image-id --docker-compose ./oracle/docker-compose.yml --arch amd64`
5. **Derive new pubkey**: `oyster-cvm kms-derive --image-id <NEW_ID> --path oracle-price-feed --key-type ed25519/public`
6. **Convert pubkey**: `echo -n "<hex>" | xxd -r -p | base64` (Octra needs base64)
7. **Deploy new enclave**: `oyster-cvm deploy ...`
8. **Verify oracle health**: `curl http://<NEW_IP>:8080/health`
9. **Update deploy.py** with new `ORACLE_PUBKEY`
10. **Redeploy contract** (new pubkey = new contract)
11. **Test relay** end-to-end

**Note**: New image = new image ID = new KMS-derived keypair = must redeploy the contract with the new pubkey.

## Step-by-Step: Deploy Oracle & Relay Price

Quick-reference for deploying the oracle and getting a price on-chain. Assumes same image (no pubkey change).

### 1. Deploy the enclave (30 min budget)

```bash
source .env
oyster-cvm deploy \
  --wallet-private-key "${ARBITRUM_PRIVATE_KEY#0x}" \
  --docker-compose ./oracle/docker-compose.yml \
  --duration-in-minutes 30 \
  --region us-east-1 \
  --arch amd64
```

Wait ~3 min for boot. Note the IP address from output.

**Important:** The `--wallet-private-key` must NOT have a `0x` prefix (hence the `${VAR#0x}` strip).

### 2. Verify oracle is responding

```bash
curl -X POST http://<IP>:8080/latest \
  -H "Content-Type: application/json" \
  -d @oracle/spec.json
```

Should return JSON with `value`, `timestamp`, `signature`, `public_key`.

### 3. Run the relay (one-shot)

```bash
source .env
OCTRA_SEED="$OCTRA_SEED" \
ORACLE_URL=http://<IP>:8080 \
ORACLE_SPEC_FILE=oracle/spec.json \
OCTUSD_CONTRACT=oct2hJMZbBdAAKTBXK61vs1TUx8oQNZVZyEpR4SXGFXgtvE \
python3 scripts/relay.py
```

Expected output includes `TX result: {"tx_hash": "...", "status": "accepted", ...}`.

### 4. Verify on-chain

```bash
curl -s -X POST https://octra.network/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"contract_call","params":["oct2hJMZbBdAAKTBXK61vs1TUx8oQNZVZyEpR4SXGFXgtvE","get_octra_price",[],"octEfXCJva6oTHpvZYf3i2MypeJ2BwHcbe2ziVhnTaWpi9J"],"id":1}'
```

The `oct_usd_price` field in storage should reflect the new value.

### 5. (Optional) Run in loop mode

```bash
RELAY_LOOP=1 RELAY_INTERVAL=120 \
OCTRA_SEED="..." ORACLE_URL=http://<IP>:8080 \
ORACLE_SPEC_FILE=oracle/spec.json \
OCTUSD_CONTRACT=oct2hJMZbBdAAKTBXK61vs1TUx8oQNZVZyEpR4SXGFXgtvE \
python3 scripts/relay.py
```

### 6. Check / stop the job when done

```bash
# List active jobs
oyster-cvm list --address 0x9894d145331254a78666866159c5e16D307f1006

# Stop (unreliable — prefer cast jobClose)
oyster-cvm stop --wallet-private-key <KEY> --job-id <JOB_ID>
```

### Common Pitfalls

- **Wrong contract address**: The OctUSD contract is at `oct2hJMZbBdAAKTBXK61vs1TUx8oQNZVZyEpR4SXGFXgtvE`, NOT the wallet address.
- **Job expired**: Oracle jobs have a fixed duration. If the IP is unreachable, the job likely expired — redeploy.
- **webcli hangs**: Don't use webcli for relay. The relay script signs directly via `pynacl` and submits to `octra_submit` RPC.
- **Octra RPC URL**: Always use `https://octra.network/rpc`. The old IP `46.101.86.250:8080` is unreliable.
