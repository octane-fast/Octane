# Octane Wallet — Browser Extension

Chrome MV3 extension wallet for the Octra network with shielded (FHE-encrypted) balances.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  dApp Page                                                          │
│  window.octra.request(...)                                          │
└──────────────┬──────────────────────────────────────────────────────┘
               │ postMessage
┌──────────────▼──────────────────────────────────────────────────────┐
│  inpage/index.ts          — Injected into page context              │
│  Exposes window.octra API (RFC-O-1)                                 │
└──────────────┬──────────────────────────────────────────────────────┘
               │ postMessage
┌──────────────▼──────────────────────────────────────────────────────┐
│  content/index.ts         — Content script (runs in isolated world) │
│  Relays between page ↔ background via chrome.runtime                │
└──────────────┬──────────────────────────────────────────────────────┘
               │ chrome.runtime.sendMessage
┌──────────────▼──────────────────────────────────────────────────────┐
│  background/index.ts      — Service worker (the brain)              │
│  • Wallet ops (sign, send, balance decrypt)                         │
│  • Prover orchestration (native → remote → WASM)                    │
│  • Stealth detection & claiming                                     │
│  • dApp request routing + approval flows                            │
│  • Tor proxy management                                             │
└───┬──────────────┬─────────────────────────────────────┬────────────┘
    │              │                                     │
    │ fetch        │ chrome.runtime.connect              │ chrome.runtime.sendMessage
    ▼              ▼                                     ▼
┌────────┐  ┌──────────────────────────────┐  ┌─────────────────────┐
│Octra   │  │ offscreen/index.ts           │  │ popup/              │
│RPC Node│  │ Offscreen doc — routes to    │  │ User-facing UI      │
└────────┘  │ PVAC Web Worker              │  └─────────────────────┘
            └──────────────┬───────────────┘
                           │ Worker.postMessage
            ┌──────────────▼───────────────┐
            │ offscreen/worker.ts           │
            │ PVAC WASM (heavy compute)     │
            └──────────────────────────────-┘
```

## Source Structure

```
src/
├── background/
│   └── index.ts              # Service worker — ALL wallet logic lives here
│
├── popup/
│   ├── index.html            # Main wallet popup (create/import/send/receive)
│   ├── index.ts              # Popup logic — talks to background via messages
│   ├── confirm.html          # dApp approval popup (connect/sign/send)
│   ├── confirm.ts            # Approval flow logic
│   └── styles.css            # All popup styling
│
├── content/
│   └── index.ts              # Content script — page ↔ background bridge
│
├── inpage/
│   └── index.ts              # Page-context injection — window.octra API
│
├── offscreen/
│   ├── index.ts              # Offscreen document — manages PVAC worker
│   └── worker.ts             # Web Worker running PVAC WASM proofs
│
└── lib/                      # Shared libraries (imported by background + popup)
    ├── keyVault.ts           # ⚡ Seed oracle — sign/derive, seed never exported
    ├── pvac.ts               # PVAC WASM wrapper (encrypt/decrypt/prove)
    ├── crypto.ts             # Ed25519, BIP39 mnemonic, base64
    ├── crypto/stealth.ts     # X25519 ECDH for stealth addresses
    ├── rpc.ts                # JSON-RPC client with retries
    ├── storage.ts            # AES-GCM encrypted chrome.storage layer
    ├── explorer.ts           # OctraScan URL helpers
    ├── types.ts              # Shared TypeScript interfaces
    └── pvac-wasm/            # PVAC FHE engine (Emscripten build)
        ├── pvac.js           # Pre-built WASM glue (662KB, inline WASM)
        ├── build.sh          # Rebuild script (requires emscripten)
        └── src/              # C++ binding sources
```

## Key Concepts

### PVAC Key Lifecycle

1. **Wallet import/create** → WASM derives PVAC keys from ed25519 seed (one-time, ~3s)
2. **Keys persisted** → `chrome.storage.local` keyed by `pvacKeys_${hdIndex}`
3. **Every unlock after** → keys loaded from storage instantly (no WASM)
4. **New account** → WASM derives that account's keys, persists them
5. **Operations** → background sends serialized `pvac_sk_b64` + `pvac_pk_b64` to prover

### Prover Cascade (decrypt/prove operations)

1. **Native** — Octane Accelerator on `localhost:19876` (fastest)
2. **Remote** — Via Cloudflare relay WebSocket (if paired)
3. **WASM** — Offscreen Web Worker (fallback, always available)

### Security Boundaries

- `keyVault.ts` — raw ed25519 seed NEVER leaves this module
- PVAC keys (sk/pk) are NOT value-securing — they're privacy keys
- Prover only receives serialized PVAC keys, never the signing seed
- chrome.storage.local holds encrypted mnemonic (AES-GCM + PBKDF2)

## Install from Source

### Prerequisites

- Node.js 18+
- Emscripten 5+ (only if rebuilding WASM — `brew install emscripten`)

### Build

```bash
cd wallet/extension
npm install
npm run build
```

Produces `dist/` with all bundled assets.

### Load in Chrome

1. `chrome://extensions` → Enable **Developer mode**
2. **Load unpacked** → select the `wallet/extension` folder
3. Octane Wallet icon appears in toolbar

### Rebuild After Changes

```bash
npm run build
```

Then click refresh on the extension card in `chrome://extensions`.

### Development Mode

```bash
npm run dev
```

Watches for changes and rebuilds. Still requires manual extension reload.

## PVAC WASM (Shielded Transactions)

The FHE/ZK proof engine is pre-built at `src/lib/pvac-wasm/pvac.js`. To rebuild:

```bash
cd src/lib/pvac-wasm
bash build.sh
```

Requires Emscripten. See `src/lib/pvac-wasm/README.md` for vendored code details.

## Message Protocol

The popup and content scripts communicate with the background via `chrome.runtime.sendMessage`:

| Message Type | Direction | Purpose |
|---|---|---|
| `UNLOCK` | popup → bg | Decrypt mnemonic, unlock vault |
| `LOCK` | popup → bg | Clear vault state |
| `DERIVE_PVAC_KEYS` | popup → bg | One-time WASM key derivation |
| `GET_BALANCE` | popup → bg | Fetch public balance |
| `GET_ENCRYPTED_BALANCE` | popup → bg | Fetch + decrypt private balance |
| `SEND` | popup → bg | Submit transfer transaction |
| `SHIELD` | popup → bg | Public → private (encrypt + prove) |
| `UNSHIELD` | popup → bg | Private → public (decrypt + prove) |
| `SWITCH_ACCOUNT` | popup → bg | Change active HD account |
| `ADD_ACCOUNT` | popup → bg | Derive new HD account address |
| `CONNECT` / `SIGN` / `SEND_TX` | content → bg | dApp requests (routed to confirm popup) |

## Running Tests

```bash
node --max-old-space-size=4096 test/pvac_api.cjs
```
