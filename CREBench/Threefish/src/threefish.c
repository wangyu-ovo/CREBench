/*
 * Adapted for CREBench from public Threefish implementations.
 *
 * Main reference attributions:
 *   - Crypto++ (threefish.cpp):
 *       written and placed in the public domain by Jeffrey Walton
 *       based on public-domain code by Keru Kuro
 *   - Botan (threefish_512.cpp):
 *       Copyright (C) 2013, 2014, 2016 Jack Lloyd
 *       Botan is released under the Simplified BSD License
 *   - RustCrypto (block-ciphers/threefish):
 *       Copyright (c) The Rust-Crypto Project Developers
 *       License: MIT OR Apache-2.0
 */

#include "threefish.h"

#include <string.h>

#define THREEFISH_512_ROUNDS 72

#ifdef CONSTXOR_THREEFISH_TABLES
#include "constxor_tables.h"
#define THREEFISH_C240_VALUE (constxor_threefish_c240()[0])
#define THREEFISH_R512_TABLE ((const uint8_t (*)[4])constxor_threefish_r512())
#define THREEFISH_P512_TABLE (constxor_threefish_p512())
#else
static const uint64_t threefish_c240[1] = {0x1BD11BDAA9FC1A22ULL};
static const uint8_t r512[8][4] = {
    {46, 36, 19, 37},
    {33, 27, 14, 42},
    {17, 49, 36, 39},
    {44, 9, 54, 56},
    {39, 30, 34, 24},
    {13, 50, 10, 17},
    {25, 29, 39, 43},
    {8, 35, 56, 22}
};

static const uint8_t p512[8] = {6, 1, 0, 7, 2, 5, 4, 3};
#define THREEFISH_C240_VALUE (threefish_c240[0])
#define THREEFISH_R512_TABLE (r512)
#define THREEFISH_P512_TABLE (p512)
#endif

static inline uint64_t load_le64(const uint8_t *p)
{
    return ((uint64_t)p[0]) |
           ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

static inline void store_le64(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

static inline uint64_t rotl64(uint64_t x, uint32_t n)
{
    return (x << n) | (x >> (64 - n));
}

static inline uint64_t rotr64(uint64_t x, uint32_t n)
{
    return (x >> n) | (x << (64 - n));
}

static void threefish512_update_subkeys(threefish512_ctx *ctx)
{
    uint64_t k[9];
    uint64_t t[3];

    uint64_t kxor = THREEFISH_C240_VALUE;
    for (size_t i = 0; i < 8; i++) {
        k[i] = ctx->key_words[i];
        kxor ^= k[i];
    }
    k[8] = kxor;

    t[0] = ctx->tweak_words[0];
    t[1] = ctx->tweak_words[1];
    t[2] = t[0] ^ t[1];

    for (size_t s = 0; s <= THREEFISH_512_ROUNDS / 4; s++) {
        for (size_t i = 0; i < 8; i++) {
            uint64_t val = k[(s + i) % 9];
            if (i == 5) {
                val += t[s % 3];
            } else if (i == 6) {
                val += t[(s + 1) % 3];
            } else if (i == 7) {
                val += (uint64_t)s;
            }
            ctx->subkeys[s][i] = val;
        }
    }
}

int threefish512_set_key(threefish512_ctx *ctx, const uint8_t *key, size_t key_len)
{
    if (!ctx || !key || key_len != THREEFISH_512_KEY_SIZE) {
        return -1;
    }

    for (size_t i = 0; i < 8; i++) {
        ctx->key_words[i] = load_le64(key + i * 8);
    }

    ctx->tweak_words[0] = 0;
    ctx->tweak_words[1] = 0;
    threefish512_update_subkeys(ctx);

    return 0;
}

int threefish512_set_tweak(threefish512_ctx *ctx, const uint8_t *tweak, size_t tweak_len)
{
    if (!ctx || !tweak || tweak_len != THREEFISH_TWEAK_SIZE) {
        return -1;
    }

    ctx->tweak_words[0] = load_le64(tweak);
    ctx->tweak_words[1] = load_le64(tweak + 8);
    threefish512_update_subkeys(ctx);

    return 0;
}

void threefish512_encrypt_block(const threefish512_ctx *ctx, const uint8_t *in, uint8_t *out)
{
    uint64_t block[8];
    uint64_t temp[8];

    for (size_t i = 0; i < 8; i++) {
        block[i] = load_le64(in + i * 8);
    }

    for (size_t d = 0; d < THREEFISH_512_ROUNDS; d++) {
        memcpy(temp, block, sizeof(block));
        for (size_t j = 0; j < 4; j++) {
            uint64_t x0 = temp[2 * j];
            uint64_t x1 = temp[2 * j + 1];
            if ((d % 4) == 0) {
                x0 += ctx->subkeys[d / 4][2 * j];
                x1 += ctx->subkeys[d / 4][2 * j + 1];
            }
            uint64_t y0 = x0 + x1;
            uint64_t y1 = rotl64(x1, THREEFISH_R512_TABLE[d % 8][j]) ^ y0;
            block[THREEFISH_P512_TABLE[2 * j]] = y0;
            block[THREEFISH_P512_TABLE[2 * j + 1]] = y1;
        }
    }

    for (size_t i = 0; i < 8; i++) {
        block[i] += ctx->subkeys[THREEFISH_512_ROUNDS / 4][i];
    }

    for (size_t i = 0; i < 8; i++) {
        store_le64(out + i * 8, block[i]);
    }
}

void threefish512_decrypt_block(const threefish512_ctx *ctx, const uint8_t *in, uint8_t *out)
{
    uint64_t block[8];
    uint64_t temp[8];

    for (size_t i = 0; i < 8; i++) {
        block[i] = load_le64(in + i * 8);
    }

    for (size_t i = 0; i < 8; i++) {
        block[i] -= ctx->subkeys[THREEFISH_512_ROUNDS / 4][i];
    }

    for (size_t d = THREEFISH_512_ROUNDS; d-- > 0;) {
        memcpy(temp, block, sizeof(block));
        for (size_t j = 0; j < 4; j++) {
            uint64_t y0 = temp[THREEFISH_P512_TABLE[2 * j]];
            uint64_t y1 = temp[THREEFISH_P512_TABLE[2 * j + 1]];
            uint64_t x1 = rotr64(y0 ^ y1, THREEFISH_R512_TABLE[d % 8][j]);
            uint64_t x0 = y0 - x1;
            if ((d % 4) == 0) {
                x0 -= ctx->subkeys[d / 4][2 * j];
                x1 -= ctx->subkeys[d / 4][2 * j + 1];
            }
            block[2 * j] = x0;
            block[2 * j + 1] = x1;
        }
    }

    for (size_t i = 0; i < 8; i++) {
        store_le64(out + i * 8, block[i]);
    }
}

void threefish512_cbc_encrypt(const threefish512_ctx *ctx,
                              const uint8_t *iv,
                              const uint8_t *in,
                              uint8_t *out,
                              size_t len)
{
    uint8_t prev[THREEFISH_512_BLOCK_SIZE];
    uint8_t block[THREEFISH_512_BLOCK_SIZE];
    size_t i;
    int j;

    memcpy(prev, iv, THREEFISH_512_BLOCK_SIZE);

    for (i = 0; i < len; i += THREEFISH_512_BLOCK_SIZE) {
        for (j = 0; j < THREEFISH_512_BLOCK_SIZE; j++) {
            block[j] = in[i + (size_t)j] ^ prev[j];
        }
        threefish512_encrypt_block(ctx, block, &out[i]);
        memcpy(prev, &out[i], THREEFISH_512_BLOCK_SIZE);
    }
}

void threefish512_cbc_decrypt(const threefish512_ctx *ctx,
                              const uint8_t *iv,
                              const uint8_t *in,
                              uint8_t *out,
                              size_t len)
{
    uint8_t prev[THREEFISH_512_BLOCK_SIZE];
    uint8_t temp[THREEFISH_512_BLOCK_SIZE];
    uint8_t block[THREEFISH_512_BLOCK_SIZE];
    size_t i;
    int j;

    memcpy(prev, iv, THREEFISH_512_BLOCK_SIZE);

    for (i = 0; i < len; i += THREEFISH_512_BLOCK_SIZE) {
        memcpy(temp, &in[i], THREEFISH_512_BLOCK_SIZE);
        threefish512_decrypt_block(ctx, &in[i], block);
        for (j = 0; j < THREEFISH_512_BLOCK_SIZE; j++) {
            out[i + (size_t)j] = block[j] ^ prev[j];
        }
        memcpy(prev, temp, THREEFISH_512_BLOCK_SIZE);
    }
}
