# Octane Wallet — Browser Extension

Chrome extension wallet for the Octra network with shielded (FHE-encrypted) balances.

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

This produces the `dist/` folder with all bundled assets.

### Load in Chrome

1. Open `chrome://extensions`
2. Enable **Developer mode** (toggle in top-right)
3. Click **Load unpacked**
4. Select the `wallet/extension` folder (the one containing `manifest.json`)
5. The Octane Wallet icon appears in your toolbar

### Rebuild After Changes

```bash
npm run build
```

Then click the refresh icon on the extension card in `chrome://extensions`.

### Development Mode

```bash
npm run dev
```

Watches for file changes and rebuilds automatically. Still requires manual extension reload in Chrome.

## PVAC WASM (Shielded Transactions)

The FHE/ZK proof engine is pre-built at `src/lib/pvac-wasm/pvac.js`. To rebuild from source:

```bash
cd src/lib/pvac-wasm
bash build.sh
```

Requires Emscripten. See `src/lib/pvac-wasm/README.md` for details on vendored code and patches.

## Running Tests

```bash
node --max-old-space-size=4096 test/pvac_api.cjs
```
