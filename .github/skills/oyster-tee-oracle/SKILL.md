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

Note: `stop` sets rate to 0, then waits 5 minutes before closing. May fail with "execution reverted" if job is in a transitional state — just wait for expiry.

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
```bash
curl http://<INSTANCE_IP>:8080/latest
```

Returns:
```json
{
  "price": 43654,
  "epoch": 1778877231,
  "message": "43654:1778877231",
  "signature": "<hex-encoded ed25519 signature>",
  "public_key": "<hex-encoded ed25519 public key>",
  "price_usd": 0.04365,
  "sources_used": 1
}
```

### Relaying to Octra Contract

1. Fetch attestation from TEE oracle
2. Convert signature from hex to base64 (Octra's `ed25519_ok` requires base64)
3. Submit to contract via webcli:

```python
import base64, binascii

sig_hex = attestation["signature"]
sig_b64 = base64.b64encode(binascii.unhexlify(sig_hex)).decode()

# Call contract
requests.post("http://127.0.0.1:8420/api/contract/call", json={
    "address": CONTRACT_ADDR,
    "method": "update_octra_price",
    "params": [attestation["price"], attestation["epoch"], sig_b64],
    "ou": "200000"
})
```

## Current Deployment Info

- Wallet address: `0x9894d145331254a78666866159c5e16D307f1006`
- Oracle image: `xxx/octusd-oracle:latest`
- Oracle pubkey (hex): `e5e83354098289baa2ba5d962dfc504ae4e2337a38addc7208b9e09370cc7368`
- Oracle pubkey (b64): `5egzVAmCibqiul2WLfxQSuTiM3o4rdxyCLngk3DMc2g=`
- KMS derive path: `oracle-price-feed`
- Image ID: `0994afac81f3b43bcc7d9823d34b357c0cd692bc33fb4364b0a4d838c30ac67e`

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Deploy blocks forever | The 3-min wait is normal; kill terminal and check `list` |
| Stop fails with "reverted" | Use `cast` to call `jobClose` directly (see below) |
| Old IP unreachable | Instance was recycled; deploy a new one |
| Signature invalid on-chain | Convert hex → base64 before submitting |

### Force-Kill a Stuck Job

When `oyster-cvm stop` reverts, call `jobClose` directly on the Arbitrum marketplace contract:

```bash
cast send 0x9d95D61eA056721E358BC49fE995caBF3B86A34B \
  "jobClose(bytes32)" \
  0x000000000000000000000000000000000000000000000000000000000000XXXX \
  --private-key 0x<YOUR_KEY> \
  --rpc-url https://arb1.arbitrum.io/rpc
```

This bypasses the rate-revise step and terminates the job immediately, refunding remaining USDC.
