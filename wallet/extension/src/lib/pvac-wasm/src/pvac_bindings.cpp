/**
 * PVAC WASM bindings for Octane Wallet
 * FILE: src/pvac_bindings.cpp
 * STATUS: OUR CODE (not vendored)
 *
 * Exposes the minimum set of PVAC functions needed for shield/unshield operations
 * as Emscripten-exported C functions callable from JavaScript/TypeScript.
 */

#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <emscripten/emscripten.h>

// Include PVAC C API only (implementation is in pvac_c_api.cpp)
#include "pvac_c_api.h"

// For generator precomputation at init
#include "pvac/crypto/bulletproofs/generators.hpp"

// Global state
static pvac_params g_params = nullptr;
static pvac_pubkey g_pk = nullptr;
static pvac_seckey g_sk = nullptr;

extern "C" {

EMSCRIPTEN_KEEPALIVE
int pvac_wasm_init(const uint8_t* seed, int seed_len) {
    if (seed_len < 32) return 0;
    if (g_pk) { pvac_free_pubkey(g_pk); g_pk = nullptr; }
    if (g_sk) { pvac_free_seckey(g_sk); g_sk = nullptr; }
    if (g_params) { pvac_free_params(g_params); g_params = nullptr; }

    g_params = pvac_default_params();
    pvac_keygen_from_seed(g_params, seed, &g_pk, &g_sk);
    
    // Pre-warm the generator table (used by bulletproofs prover)
    pvac::bp::generators().precompute(1024);
    
    return (g_pk && g_sk) ? 1 : 0;
}

// Encrypt a value and return serialized cipher
// Returns pointer to malloc'd buffer, caller frees via pvac_wasm_free
// Note: amount is uint32_t at the WASM boundary (max ~4294 OCT), cast to uint64_t internally
EMSCRIPTEN_KEEPALIVE
uint8_t* pvac_wasm_encrypt(uint32_t value,
                           const uint8_t* seed, int* out_len) {
    pvac_cipher ct = pvac_enc_value_seeded(g_pk, g_sk, (uint64_t)value, seed);
    size_t len = 0;
    uint8_t* data = pvac_serialize_cipher(ct, &len);
    pvac_free_cipher(ct);
    *out_len = (int)len;
    return data;
}

// Decrypt a cipher and return the value
EMSCRIPTEN_KEEPALIVE
uint32_t pvac_wasm_decrypt(const uint8_t* cipher_data, int cipher_len) {
    pvac_cipher ct = pvac_deserialize_cipher(cipher_data, (size_t)cipher_len);
    if (!ct) return 0;
    uint64_t lo = 0, hi = 0;
    pvac_dec_value_fp(g_pk, g_sk, ct, &lo, &hi);
    pvac_free_cipher(ct);
    return (uint32_t)lo;
}

// Make a Pedersen commitment
// Returns pointer to 32-byte buffer
EMSCRIPTEN_KEEPALIVE
uint8_t* pvac_wasm_pedersen_commit(uint32_t amount, const uint8_t* blinding) {
    uint8_t* out = (uint8_t*)malloc(32);
    size_t out_len = 0;
    int rc = pvac_pedersen_commit_v2((uint64_t)amount, blinding, out, 32, &out_len);
    if (rc != 0 || out_len != 32) {
        memset(out, 0, 32);
    }
    return out;
}

// Make a zero proof (bound)
// Returns serialized proof, caller frees
EMSCRIPTEN_KEEPALIVE
uint8_t* pvac_wasm_make_zero_proof_bound(const uint8_t* cipher_data, int cipher_len,
                                          uint32_t amount, const uint8_t* blinding,
                                          int* out_len) {
    pvac_cipher ct = pvac_deserialize_cipher(cipher_data, (size_t)cipher_len);
    if (!ct) { *out_len = 0; return nullptr; }
    pvac_zero_proof zp = pvac_make_zero_proof_bound(g_pk, g_sk, ct, (uint64_t)amount, blinding);
    pvac_free_cipher(ct);
    if (!zp) { *out_len = 0; return nullptr; }
    size_t len = 0;
    uint8_t* data = pvac_serialize_zero_proof(zp, &len);
    pvac_free_zero_proof(zp);
    *out_len = (int)len;
    return data;
}

// Make aggregated range proof for remaining balance
EMSCRIPTEN_KEEPALIVE
uint8_t* pvac_wasm_make_range_proof(const uint8_t* cipher_data, int cipher_len,
                                     uint32_t value, int* out_len) {
    pvac_cipher ct = pvac_deserialize_cipher(cipher_data, (size_t)cipher_len);
    if (!ct) { *out_len = 0; return nullptr; }
    pvac_agg_range_proof arp = pvac_make_aggregated_range_proof(g_pk, g_sk, ct, (uint64_t)value);
    pvac_free_cipher(ct);
    if (!arp) { *out_len = 0; return nullptr; }
    size_t len = 0;
    uint8_t* data = pvac_serialize_agg_range_proof(arp, &len);
    pvac_free_agg_range_proof(arp);
    *out_len = (int)len;
    return data;
}

// Subtract two ciphers (for computing new balance cipher after shield/unshield)
EMSCRIPTEN_KEEPALIVE
uint8_t* pvac_wasm_ct_sub(const uint8_t* a_data, int a_len,
                           const uint8_t* b_data, int b_len,
                           int* out_len) {
    pvac_cipher a = pvac_deserialize_cipher(a_data, (size_t)a_len);
    pvac_cipher b = pvac_deserialize_cipher(b_data, (size_t)b_len);
    if (!a || !b) {
        if (a) pvac_free_cipher(a);
        if (b) pvac_free_cipher(b);
        *out_len = 0;
        return nullptr;
    }
    pvac_cipher result = pvac_ct_sub(g_pk, a, b);
    pvac_free_cipher(a);
    pvac_free_cipher(b);
    size_t len = 0;
    uint8_t* data = pvac_serialize_cipher(result, &len);
    pvac_free_cipher(result);
    *out_len = (int)len;
    return data;
}

// Get serialized public key
EMSCRIPTEN_KEEPALIVE
uint8_t* pvac_wasm_get_pubkey(int* out_len) {
    size_t len = 0;
    uint8_t* data = pvac_serialize_pubkey(g_pk, &len);
    *out_len = (int)len;
    return data;
}

// Free a buffer returned by any of the above functions
EMSCRIPTEN_KEEPALIVE
void pvac_wasm_free(void* ptr) {
    free(ptr);
}

// AES KAT (needed for pvac registration)
EMSCRIPTEN_KEEPALIVE
void pvac_wasm_aes_kat(uint8_t out[16]) {
    pvac_aes_kat(out);
}

} // extern "C"
