# octUSD

Algorithmic stablecoin on [Octra](https://octra.org), backed by over-collateralized OCT reserves with TEE-verified oracle price feeds.

**Token address:** `octBmhcDw4Z8mALn7d7GdW8941FfTpqVGBBv1GDBbu4aAbj`

## Architecture

```
┌──────────────┐    POST /latest    ┌──────────────────┐   update_octra_price   ┌─────────────┐
│  Price Relay │ ─────────────────► │  TEE Oracle      │                        │  OctUSD     │
│  (scripts/)  │ ◄──────────────── │  (Oyster CVM)    │                        │  Contract   │
│              │  signed attestation│  ed25519 signing │                        │  (Octra)    │
│              │ ──────────────────────────────────────────────────────────────► │             │
└──────────────┘       webcli TX submission                                     └─────────────┘
```

- **Contract** — AML smart contract implementing the OCS-01 token standard. Mints octUSD when users deposit OCT, redeems OCT when users burn octUSD. All admin operations are timelocked (24h).
- **Oracle** — Rust binary running inside a Marlin Oyster CVM TEE enclave. Fetches prices from 3 independent sources, computes the median, and signs the result with a KMS-derived ed25519 key.
- **Relay** — Python script that queries the oracle, receives a signed attestation, and submits the price update transaction to the contract via the Octra webcli.

## Oracle Spec

The oracle fetches OCT/USD prices from 3 sources and takes the median:

```json
{
  "sources": [
    {
      "url": "https://api.coingecko.com/api/v3/simple/price?ids=octra&vs_currencies=usd",
      "resultQuery": "octra.usd"
    },
    {
      "url": "https://api.coinmarketcap.com/data-api/v3/cryptocurrency/detail?slug=octra",
      "resultQuery": "data.statistics.price"
    },
    {
      "url": "https://api.dexscreener.com/latest/dex/pairs/ethereum/0x5eb459d3fc44f3f412ef43f93fa1e44ecb4ca9cb62a16bcbd94b5d0b834ff854",
      "resultQuery": "to_number(pair.priceUsd)"
    }
  ],
  "aggregation": "median",
  "domain": "octusd-price-v1",
  "scale": 1000000
}
```

The `scale` factor (10^6) converts the raw float price to an integer for on-chain use. For example, $0.0415 becomes `41500`.

**Spec hash:** `29c6e50f3ad93d4856571c1e1b5cc066c4ac775bf587781f9909c4fc7f6ff163`

## Contract Features

- **Mint** — Deposit OCT, receive octUSD at the current oracle price
- **Redeem** — Burn octUSD, receive OCT back
- **Over-collateralization** — Configurable collateral ratio (default 4x) enforced on every mint
- **Fees** — Configurable mint/redeem fees in basis points
- **Hold time** — Optional minimum hold period before transfers or redemptions
- **Transmitter whitelist** — Optional restriction on who can submit price updates
- **Timelocked governance** — All admin parameter changes require a 24-hour delay

## Running the Oracle

### Prerequisites

- Rust 1.87+
- Docker

### Build & Test

```bash
cd oracle
cargo test
cargo build --release
```

### Run Locally (development)

```bash
# Without TEE (uses a random keypair)
cd oracle
PORT=8080 cargo run
```

### Deploy to Oyster CVM (production)

```bash
# Build and push Docker image
docker build -t ghcr.io/octane-defi/octusd-oracle:latest ./oracle
docker push ghcr.io/octane-defi/octusd-oracle:latest

# Update docker-compose.yml with the new image tag, then:
oyster-cvm deploy \
  --docker-compose ./oracle/docker-compose.yml \
  --wallet-private-key <ARBITRUM_KEY> \
  --duration-in-minutes 60 \
  --region ap-south-1 \
  --arch amd64

# The deploy command prints the enclave IP when ready.
# The KMS-derived public key is deterministic for a given image ID + path.
```

### Derive the Oracle Public Key

When the image changes, the keypair changes. Derive the new public key:

```bash
# Compute image ID from docker-compose
oyster-cvm compute-image-id --docker-compose ./oracle/docker-compose.yml --arch amd64

# Derive the ed25519 public key for that image
oyster-cvm kms-derive --image-id <IMAGE_ID> --path oracle-price-feed --key-type ed25519/public

# Convert hex pubkey to base64 (for the contract constructor)
echo -n "<HEX_PUBKEY>" | xxd -r -p | base64
```

### Oracle API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Returns `{"status":"ok"}` |
| `/pubkey` | GET | Returns the oracle's ed25519 public key (hex + base64) |
| `/latest` | POST | Fetches prices, aggregates, signs, and returns attestation |

**POST /latest** expects the spec JSON as the request body and returns:

```json
{
  "value": 41458.0,
  "timestamp": 1778951446,
  "domain": "octusd-price-v1",
  "spec_hash": "29c6...",
  "message": "octusd-price-v1:29c6...:41458:1778951446",
  "signature": "<base64>",
  "public_key": "<base64>",
  "sources_used": 3,
  "sources_total": 3
}
```

## Running the Relay

The relay fetches signed attestations from the oracle and submits price updates to the contract.

### Prerequisites

- Python 3.10+
- [Octra webcli](https://octra.org) running locally on port 8420
- An Octra wallet with OCT for transaction fees

### Usage

```bash
# Start the webcli wallet
/tmp/webcli/octra_wallet &

# One-shot: fetch and submit one price update
ORACLE_URL="http://<ORACLE_IP>:8080" \
ORACLE_SPEC_FILE="oracle/spec.json" \
OCTUSD_CONTRACT="octBmhcDw4Z8mALn7d7GdW8941FfTpqVGBBv1GDBbu4aAbj" \
python3 scripts/relay.py

# Loop mode: poll every 2 minutes
RELAY_LOOP=1 RELAY_INTERVAL=120 \
ORACLE_URL="http://<ORACLE_IP>:8080" \
ORACLE_SPEC_FILE="oracle/spec.json" \
OCTUSD_CONTRACT="octBmhcDw4Z8mALn7d7GdW8941FfTpqVGBBv1GDBbu4aAbj" \
python3 scripts/relay.py

# Dry run: print what would be submitted
RELAY_DRY_RUN=1 \
ORACLE_URL="http://<ORACLE_IP>:8080" \
ORACLE_SPEC_FILE="oracle/spec.json" \
OCTUSD_CONTRACT="octBmhcDw4Z8mALn7d7GdW8941FfTpqVGBBv1GDBbu4aAbj" \
python3 scripts/relay.py
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ORACLE_URL` | `http://localhost:8080` | TEE oracle HTTP endpoint |
| `ORACLE_SPEC_FILE` | *(required)* | Path to the query spec JSON file |
| `OCTUSD_CONTRACT` | *(required)* | Deployed OctUSD contract address |
| `WEBCLI_URL` | `http://localhost:8420` | Octra webcli endpoint |
| `RELAY_INTERVAL` | `120` | Seconds between polls (loop mode) |
| `RELAY_LOOP` | `0` | Set to `1` for continuous polling |
| `RELAY_DRY_RUN` | `0` | Set to `1` to skip TX submission |

## Project Structure

```
├── contracts/
│   ├── main.aml              # OctUSD contract (AML)
│   └── interfaces/
│       └── IOCS01.aml        # OCS-01 token standard interface
├── oracle/
│   ├── src/main.rs           # TEE oracle (Rust)
│   ├── spec.json             # Price source specification
│   ├── Dockerfile            # Multi-stage Alpine build
│   ├── docker-compose.yml    # Oyster CVM deployment config
│   └── Cargo.toml
├── scripts/
│   ├── deploy.py             # Contract deployment script
│   └── relay.py              # Oracle → contract price relay
└── .github/
    └── workflows/
        └── oracle-docker.yml # CI: test, build, push Docker image
```

## Deploying the Contract

```bash
# Set environment variables
export OCTRA_SEED="<your seed phrase>"
export OCTRA_PIN="<your pin>"

# Start webcli
/tmp/webcli/octra_wallet &

# Deploy (compiles and deploys in one step)
python3 scripts/deploy.py
```

The deploy script reads the oracle public key, domain, spec hash, and initial price from its constants. Update these in `scripts/deploy.py` before deploying if the oracle image has changed.

## License

MIT
