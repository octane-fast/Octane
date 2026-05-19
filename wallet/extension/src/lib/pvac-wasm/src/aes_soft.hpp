/**
 * Software AES-256-CTR for WASM — wraps vendored tiny-AES-c (public domain).
 * FILE: src/aes_soft.hpp
 * STATUS: OUR CODE (wrapper around vendored tiny-AES-c)
 *
 * This file is included instead of the #error path in vendor/pvac/pvac/crypto/lpn.hpp
 * for WASM builds where neither x86 AES-NI nor ARM crypto extensions are available.
 *
 * The raw AES-256 block cipher (ECB mode) comes from:
 *   vendor/tiny-aes-c/ — https://github.com/kokke/tiny-AES-c (Unlicense/public domain)
 *
 * This wrapper provides PVAC's `AesCtr256` struct interface (init, next_u64, fill_u64)
 * using PVAC's counter format: [counter_u64_LE | 8_zero_bytes] per block.
 *
 * A copy of this file lives at vendor/pvac/aes_soft.hpp for include resolution.
 * The canonical source is THIS file; the vendor copy is synced by build.sh.
 */
#pragma once
#include <cstdint>
#include <cstring>

// ---------------------------------------------------------------------------
// Inline the tiny-AES-c block cipher (AES-256 ECB encrypt only).
// We include it inline to avoid separate compilation units and link issues
// in this header-only library context.
// Source: https://github.com/kokke/tiny-AES-c (Unlicense)
// ---------------------------------------------------------------------------

// Configure for AES-256, ECB only (no CBC, no CTR — we handle CTR ourselves)
#define AES256 1
#define ECB    1
#define CBC    0
#define CTR    0

// Bring in tiny-AES-c declarations only.
// The implementation (aes.c) is compiled as a separate translation unit — see build.sh.
extern "C" {
#include "../vendor/tiny-aes-c/aes.h"
}

// ---------------------------------------------------------------------------
// PVAC-compatible AesCtr256 struct using tiny-AES-c for the block cipher.
// Counter format matches PVAC's x86/ARM implementations:
//   block = [ctr_val as uint64_t LE][8 zero bytes]
// ---------------------------------------------------------------------------

struct AesCtr256 {
    struct AES_ctx ecb_ctx;
    uint64_t ctr_val;
    alignas(16) uint64_t buf[2] = {0, 0};
    bool has_buf = false;

    void init(const uint8_t key[32], uint64_t nonce) {
        AES_init_ctx(&ecb_ctx, key);
        ctr_val = nonce;
        has_buf = false;
    }

    inline void encrypt_ctr_block(uint8_t out[16]) {
        // Build counter block: [ctr_val LE | zeros]
        std::memset(out, 0, 16);
        std::memcpy(out, &ctr_val, 8);
        // ECB-encrypt in place
        AES_ECB_encrypt(&ecb_ctx, out);
        ++ctr_val;
    }

    inline uint64_t next_u64() {
        if (has_buf) {
            has_buf = false;
            return buf[1];
        }
        alignas(16) uint8_t tmp[16];
        encrypt_ctr_block(tmp);
        std::memcpy(buf, tmp, 16);
        has_buf = true;
        return buf[0];
    }

    inline void fill_u64(uint64_t* out, size_t n) {
        size_t i = 0;
        if (has_buf && n > 0) {
            out[0] = buf[1];
            has_buf = false;
            i = 1;
        }
        alignas(16) uint8_t tmp[16];
        alignas(16) uint64_t pair[2];
        for (; i + 1 < n; i += 2) {
            encrypt_ctr_block(tmp);
            std::memcpy(pair, tmp, 16);
            out[i] = pair[0];
            out[i + 1] = pair[1];
        }
        if (i < n) {
            encrypt_ctr_block(tmp);
            std::memcpy(buf, tmp, 16);
            out[i] = buf[0];
            has_buf = true;
        }
    }

    inline uint64_t bounded(uint64_t M) {
        if (M <= 1) return 0;
        uint64_t lim = UINT64_MAX - (UINT64_MAX % M);
        for (;;) {
            uint64_t x = next_u64();
            if (x < lim) return x % M;
        }
    }
};
