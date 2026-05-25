# octUSD

Algorithmic stablecoin on [Octra](https://octra.org), backed by over-collateralized OCT reserves with TEE-verified oracle price feeds.

**Token address:** `oct2hJMZbBdAAKTBXK61vs1TUx8oQNZVZyEpR4SXGFXgtvE`

The octUSD stablecoin enables DeFi on Octra. The token is algorithmic; it is backed by OCT, the native token of the Octra network. A user can obtain octUSD by depositing OCT, and are issued an octUSD amount that corresponds to the value of that OCT they deposit. In order to price OCT, a TEE-based oracle runs and provides price updates for the OCT token. This TEE uses an ed25519 signing key that is never exposed to the outside world, and can be operated by anyone. Feel free to run the TEE oracle yourself and start issuing price updates to octUSD: you can do so by following the `Running the Oracle` section. 

The Docker Image used to generate the TEE binary can be viewed here: https://github.com/octane-defi/octUSD/actions/runs/25967564381/attempts/1#summary-76333668042. The Docker Image, and subsequently the enclave binary, serves as the derivation path for the oracle signing key. The public key of this oracle can be seen in the [genesis transaction](https://octrascan.io/tx.html?hash=8e8ac7ad63ecd6cfc067b7cc90e1d2b7313026ba11f39c9effa238c3780ee642), and is: `CHkfB7TkASlpfzvSdNArXbaxm2Z/uOXahrDhenL7rz4=`. Learn more about this process here: https://docs.marlin.org/oyster/build-cvm/tutorials/persistent-keys.

Currently, OCT reserves must exceed the value of all octUSD by 1.5x. If that ratio is violated, minting new USD is disabled until the reserves are replenished. As the ecosystem matures, different wrapped tokens representing forms of collateral, including Bitcoin, Ethereum, Gold, or US Treasuries, may be incorporated into the token's reserves.

This token is experimental and has not been audited. Review the program code, and use at your own risk.

## Quick Start

For now, the easiest way to interact with octUSD is to make API calls to the Octra WebCLI. The WebCLI can be downlaoded [here](https://github.com/octra-labs/octra-webcli). Once it is running: 

**Mint octUSD (deposits 1 OCT):**
```bash
curl -s http://127.0.0.1:8420/api/contract/call \
  -H 'Content-Type: application/json' \
  -d '{"address":"oct2hJMZbBdAAKTBXK61vs1TUx8oQNZVZyEpR4SXGFXgtvE","method":"mint","params":[],"ou":"1000","amount":"1000000"}'
```

**Redeem 1 octUSD for OCT:**
```bash
curl -s http://127.0.0.1:8420/api/contract/call \
  -H 'Content-Type: application/json' \
  -d '{"address":"oct2hJMZbBdAAKTBXK61vs1TUx8oQNZVZyEpR4SXGFXgtvE","method":"redeem","params":[1],"ou":"1000","amount":"0"}'
```

## Architecture

```
┌────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│  Data Sources  │         │  TEE Oracle      │         │  OctUSD         │
│                │◄────────┤                  │         │  Contract       │
│                │  fetch  │                  │         │                 │
└────────────────┘         └────────┬─────────┘         └─────────▲───────┘
                                    │ signed price update         │
                                    │                             │
                           ┌────────▼─────────┐                   │
                           │  Price Relay     │                   │ update_octra_price
                           │                  ├───────────────────┘
                           └──────────────────┘
```

- **Contract** — AML smart contract implementing the OCS-01 token standard. Mints octUSD when users deposit OCT, redeems OCT when users burn octUSD. All admin operations are timelocked (1hr).
- **Oracle** — Rust binary running inside a Marlin Oyster CVM TEE. Fetches prices from 3 independent sources, computes the median, and signs the result with a KMS-derived ed25519 key.
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

**Spec hash:** `29c6e50f3ad93d4856571c1e1b5cc066c4ac775bf587781f9909c4fc7f6ff163`

This hash is used within the octUSD token contract. It is a hash of the above plaintext configuration, and ensures that only this configuration is used when querying the TEE-based oracle for price data. I.e., an adversary cannot query alternative datasources to create a fraudulent price update.

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
# Build and push Docker image (CI does this automatically on push)
# Image tags use the git SHA, e.g. ghcr.io/octane-defi/octusd-oracle:sha-4882472
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
OCTUSD_CONTRACT="oct2hJMZbBdAAKTBXK61vs1TUx8oQNZVZyEpR4SXGFXgtvE" \
python3 scripts/relay.py

# Loop mode: poll every 2 minutes
RELAY_LOOP=1 RELAY_INTERVAL=120 \
ORACLE_URL="http://<ORACLE_IP>:8080" \
ORACLE_SPEC_FILE="oracle/spec.json" \
OCTUSD_CONTRACT="oct2hJMZbBdAAKTBXK61vs1TUx8oQNZVZyEpR4SXGFXgtvE" \
python3 scripts/relay.py

# Dry run: print what would be submitted
RELAY_DRY_RUN=1 \
ORACLE_URL="http://<ORACLE_IP>:8080" \
ORACLE_SPEC_FILE="oracle/spec.json" \
OCTUSD_CONTRACT="oct2hJMZbBdAAKTBXK61vs1TUx8oQNZVZyEpR4SXGFXgtvE" \
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
