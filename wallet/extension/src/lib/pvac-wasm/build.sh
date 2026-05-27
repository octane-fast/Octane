#!/usr/bin/env bash
# ============================================================================
# PVAC-WASM Build Script
# Compiles PVAC C++ library to WebAssembly for Octane Wallet extension.
#
# Requirements:
#   - Emscripten (brew install emscripten)
#
# Output:
#   - pvac.js (~650KB, WASM embedded inline via SINGLE_FILE)
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Find emcc
if command -v emcc &>/dev/null; then
    EMCC=emcc
elif [[ -x "/opt/homebrew/opt/emscripten/bin/emcc" ]]; then
    EMCC="/opt/homebrew/opt/emscripten/bin/emcc"
else
    echo "ERROR: emcc not found. Install with: brew install emscripten" >&2
    exit 1
fi

echo "Using emcc: $($EMCC --version | head -1)"
echo "Building PVAC WASM..."

# Ensure vendor aes_soft.hpp is in sync with src/
cp src/aes_soft.hpp vendor/pvac/aes_soft.hpp

# Step 1: Compile tiny-AES-c (C code, separate TU to avoid name collisions)
$EMCC -O3 -msimd128 -mbulk-memory -flto -c \
  -DAES256=1 -DECB=1 -DCBC=0 -DCTR=0 \
  vendor/tiny-aes-c/aes.c \
  -o /tmp/pvac_tiny_aes.o

# Step 2: Compile + link C++ sources with the C object
$EMCC -O3 -msimd128 -mbulk-memory -flto \
  -s WASM=1 \
  -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap","getValue","setValue","HEAPU8"]' \
  -s EXPORTED_FUNCTIONS='["_pvac_wasm_init","_pvac_wasm_init_from_keys","_pvac_wasm_encrypt","_pvac_wasm_decrypt","_pvac_wasm_decrypt64","_pvac_wasm_pedersen_commit","_pvac_wasm_make_zero_proof_bound","_pvac_wasm_make_range_proof","_pvac_wasm_ct_sub","_pvac_wasm_commit_ct","_pvac_wasm_get_pubkey","_pvac_wasm_get_seckey","_pvac_wasm_free","_pvac_wasm_aes_kat","_malloc","_free"]' \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s MAXIMUM_MEMORY=2147483648 \
  -s MODULARIZE=1 \
  -s EXPORT_NAME='PvacModule' \
  -s EXPORT_ES6=1 \
  -s ENVIRONMENT='web,worker' \
  -s SINGLE_FILE=1 \
  -s INITIAL_MEMORY=67108864 \
  -s STACK_SIZE=8388608 \
  -DNDEBUG -DAES256=1 -DECB=1 -DCBC=0 -DCTR=0 \
  -I./src \
  -I./vendor/pvac \
  -I./vendor \
  /tmp/pvac_tiny_aes.o \
  src/pvac_bindings.cpp \
  src/pvac_c_api.cpp \
  -o pvac.js \
  --no-entry \
  -std=c++17

echo "Done! Output: pvac.js ($(wc -c < pvac.js | tr -d ' ') bytes)"
