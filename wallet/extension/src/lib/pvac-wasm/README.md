# PVAC-WASM — Homomorphic FHE for Octane Wallet

This directory compiles the [PVAC-HFHE](https://github.com/nickthorpe71/pvac) C++
library to WebAssembly for use in the Octane browser extension.

## Directory Structure

```
pvac-wasm/
├── README.md              ← You are here
├── build.sh               ← Build script (requires Emscripten)
├── .gitignore             ← Ignores build output (pvac.js)
│
├── vendor/                ← UPSTREAM / VENDORED code (do not edit in place)
│   ├── tiny-aes-c/      ← https://github.com/kokke/tiny-AES-c (Unlicense)
│   │   ├── aes.c        ← AES block cipher implementation
│   │   ├── aes.h        ← AES header
│   │   └── unlicense.txt
│   └── pvac/             ← Copy of pvac/include/ from upstream
│       ├── aes_soft.hpp  ← [AUTO-SYNCED] copy of src/aes_soft.hpp
│       └── pvac/
│           ├── pvac.hpp
│           ├── core/     ← Unchanged from upstream
│           ├── crypto/   ← lpn.hpp PATCHED (see below)
│           ├── ops/      ← Unchanged from upstream
│           └── utils/    ← Unchanged from upstream
│
├── src/                   ← OUR CODE (Octane-specific)
│   ├── aes_soft.hpp      ← CTR wrapper around tiny-AES-c (PVAC interface)
│   ├── pvac_c_api.h      ← C API header wrapping PVAC C++ types
│   ├── pvac_c_api.cpp    ← C API implementation
│   ├── pvac_serialize.hpp← Binary serialization (cipher, proofs, keys)
│   └── pvac_bindings.cpp ← Emscripten/WASM entry points
│
└── pvac.js                ← BUILD OUTPUT (gitignored, ~655KB w/ inline WASM)
```

## Provenance

| Path | Origin | License | Status |
|------|--------|---------|--------|
| `vendor/tiny-aes-c/` | [kokke/tiny-AES-c](https://github.com/kokke/tiny-AES-c) | **Unlicense** (public domain) | Unmodified |
| `vendor/pvac/pvac/` | [pvac upstream](https://github.com/nickthorpe71/pvac) `include/` | (check upstream) | **Patched** (lpn.hpp + generators.hpp) |
| `vendor/pvac/aes_soft.hpp` | Auto-copied from `src/aes_soft.hpp` by build.sh | Ours | Auto-synced |
| `src/aes_soft.hpp` | Written for this project (thin CTR wrapper) | Ours | **Ours** |
| `src/pvac_c_api.*` | Written for this project | Ours | **Ours** |
| `src/pvac_serialize.hpp` | Written for this project | Ours | **Ours** |
| `src/pvac_bindings.cpp` | Written for this project | Ours | **Ours** |

## Patches to Upstream PVAC

### 1. `vendor/pvac/pvac/crypto/lpn.hpp` — AES fallback for WASM

The upstream file has an `#error` directive when neither x86 AES-NI nor ARM
crypto extensions are available. WASM has neither, so we replace the `#error`
with an include of our software AES implementation:

```diff
- #error "No AES implementation available for this platform"
+ #include "../../aes_soft.hpp"
```

### 2. `vendor/pvac/pvac/crypto/bulletproofs/generators.hpp` — UB fix for WASM32

The upstream `next_power_of_2()` does `n |= n >> 32` unconditionally. On WASM32,
`size_t` is 32 bits, so shifting by 32 is **undefined behavior** (C++ requires
shift amount < bit width). At `-O2`, the compiler exploits this UB and
miscompiles the function, producing wrong buffer sizes in the bulletproofs prover
and causing out-of-bounds memory access.

```diff
  n |= n >> 16;
- n |= n >> 32;
+ #if SIZE_MAX > 0xFFFFFFFFUL
+     n |= n >> 32;
+ #endif
  return n + 1;
```

The `>> 32` is only needed on 64-bit platforms. On 32-bit targets, shifts through
`>> 16` already cover all bits.

### 3. `vendor/pvac/aes_soft.hpp` — Placed for include resolution

The patched `#include "../../aes_soft.hpp"` in `lpn.hpp` resolves to
`vendor/pvac/aes_soft.hpp`. This is a copy of `src/aes_soft.hpp`.

## AES Implementation

The raw AES-256 block cipher comes from **[tiny-AES-c](https://github.com/kokke/tiny-AES-c)**:
- **License:** Unlicense (public domain) — no restrictions whatsoever
- **Stars:** 4,700+ on GitHub, widely audited
- **Tests:** Ships with NIST SP 800-38A test vectors (ECB/CBC/CTR modes)
- **Status in our tree:** `vendor/tiny-aes-c/` — unmodified, compiled as separate C object

Our `src/aes_soft.hpp` is a **thin CTR-mode wrapper** (~50 lines) that:
- Calls `AES_ECB_encrypt()` from tiny-AES-c for each 16-byte block
- Implements PVAC's counter format: `[counter_u64_LE | 8 zero bytes]`
- Exposes PVAC's required `AesCtr256` interface (`init`, `next_u64`, `fill_u64`, `bounded`)

## Updating from Upstream

### PVAC
```bash
# 1. Clone/pull latest PVAC
git clone https://github.com/nickthorpe71/pvac /tmp/pvac-upstream

# 2. Replace vendor contents (preserving our patches)
rm -rf vendor/pvac/pvac/
cp -r /tmp/pvac-upstream/include/pvac vendor/pvac/pvac/

# 3. Re-apply patches
sed -i '' 's/#error.*/#include "..\/..\/aes_soft.hpp"/' \
  vendor/pvac/pvac/crypto/lpn.hpp

# 4. Re-apply WASM32 UB fix to generators.hpp (next_power_of_2)
sed -i '' '/n |= n >> 16;/a\
#if SIZE_MAX > 0xFFFFFFFFUL' vendor/pvac/pvac/crypto/bulletproofs/generators.hpp
sed -i '' '/n |= n >> 32;/a\
#endif' vendor/pvac/pvac/crypto/bulletproofs/generators.hpp

# 5. Rebuild (build.sh auto-syncs aes_soft.hpp to vendor/)
./build.sh
```

### tiny-AES-c
```bash
rm -rf vendor/tiny-aes-c
git clone --depth 1 https://github.com/kokke/tiny-AES-c.git vendor/tiny-aes-c
rm -rf vendor/tiny-aes-c/.git
./build.sh
```

## Building

Prerequisites: [Emscripten](https://emscripten.org/) (Homebrew: `brew install emscripten`)

```bash
./build.sh
```

Output: `pvac.js` (~650KB, WASM embedded via SINGLE_FILE mode)
