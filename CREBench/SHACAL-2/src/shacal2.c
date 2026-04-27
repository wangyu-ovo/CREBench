/*
 * Adapted for CREBench from SHACAL-2 reference implementations.
 *
 * Main references:
 *   - Crypto++:
 *       shacal2.cpp - written by Kevin Springle (2003)
 *       portions derived from Wei Dai's SHA-2 implementation
 *       original code and modifications released to the public domain
 *   - Botan:
 *       (C) 2017,2020 Jack Lloyd
 *       Botan is released under the Simplified BSD License
 */

#include "shacal2.h"

#include <string.h>

#ifdef CONSTXOR_SHACAL2_TABLES
#include "constxor_tables.h"
#define SHACAL2_RC_TABLE (constxor_shacal2_rc())
#else
static const uint32_t shacal2_rc[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcB5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};
#define SHACAL2_RC_TABLE (shacal2_rc)
#endif

static inline uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static inline void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline uint32_t rotr32(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t choose(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}

static inline uint32_t majority(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t big_sigma0(uint32_t x)
{
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

static inline uint32_t big_sigma1(uint32_t x)
{
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

static inline uint32_t small_sigma0(uint32_t x)
{
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

static inline uint32_t small_sigma1(uint32_t x)
{
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

static inline void shacal2_fwd(uint32_t A, uint32_t B, uint32_t C,
                               uint32_t *D, uint32_t E, uint32_t F,
                               uint32_t G, uint32_t *H, uint32_t rk)
{
    const uint32_t a_rho = big_sigma0(A);
    const uint32_t e_rho = big_sigma1(E);

    *H += e_rho + choose(E, F, G) + rk;
    *D += *H;
    *H += a_rho + majority(A, B, C);
}

static inline void shacal2_rev(uint32_t A, uint32_t B, uint32_t C,
                               uint32_t *D, uint32_t E, uint32_t F,
                               uint32_t G, uint32_t *H, uint32_t rk)
{
    const uint32_t a_rho = big_sigma0(A);
    const uint32_t e_rho = big_sigma1(E);

    *H -= a_rho + majority(A, B, C);
    *D -= *H;
    *H -= e_rho + choose(E, F, G) + rk;
}

int shacal2_set_key(shacal2_ctx *ctx, const uint8_t *key, size_t key_len)
{
    if (!ctx || !key || key_len < SHACAL2_MIN_KEY_SIZE || key_len > SHACAL2_MAX_KEY_SIZE ||
        (key_len % 4) != 0) {
        return -1;
    }

    memset(ctx->rk, 0, sizeof(ctx->rk));

    size_t words = key_len / 4;
    for (size_t i = 0; i < words; i++) {
        ctx->rk[i] = load_be32(key + i * 4);
    }

    for (size_t i = 16; i < 64; i++) {
        ctx->rk[i] = ctx->rk[i - 16] + small_sigma0(ctx->rk[i - 15]) +
                     ctx->rk[i - 7] + small_sigma1(ctx->rk[i - 2]);
    }

    for (size_t i = 0; i < 64; i++) {
        ctx->rk[i] += SHACAL2_RC_TABLE[i];
    }

    return 0;
}

void shacal2_encrypt_block(const shacal2_ctx *ctx, const uint8_t *in, uint8_t *out)
{
    uint32_t A = load_be32(in);
    uint32_t B = load_be32(in + 4);
    uint32_t C = load_be32(in + 8);
    uint32_t D = load_be32(in + 12);
    uint32_t E = load_be32(in + 16);
    uint32_t F = load_be32(in + 20);
    uint32_t G = load_be32(in + 24);
    uint32_t H = load_be32(in + 28);

    for (size_t r = 0; r < 64; r += 8) {
        shacal2_fwd(A, B, C, &D, E, F, G, &H, ctx->rk[r + 0]);
        shacal2_fwd(H, A, B, &C, D, E, F, &G, ctx->rk[r + 1]);
        shacal2_fwd(G, H, A, &B, C, D, E, &F, ctx->rk[r + 2]);
        shacal2_fwd(F, G, H, &A, B, C, D, &E, ctx->rk[r + 3]);
        shacal2_fwd(E, F, G, &H, A, B, C, &D, ctx->rk[r + 4]);
        shacal2_fwd(D, E, F, &G, H, A, B, &C, ctx->rk[r + 5]);
        shacal2_fwd(C, D, E, &F, G, H, A, &B, ctx->rk[r + 6]);
        shacal2_fwd(B, C, D, &E, F, G, H, &A, ctx->rk[r + 7]);
    }

    store_be32(out, A);
    store_be32(out + 4, B);
    store_be32(out + 8, C);
    store_be32(out + 12, D);
    store_be32(out + 16, E);
    store_be32(out + 20, F);
    store_be32(out + 24, G);
    store_be32(out + 28, H);
}

void shacal2_decrypt_block(const shacal2_ctx *ctx, const uint8_t *in, uint8_t *out)
{
    uint32_t A = load_be32(in);
    uint32_t B = load_be32(in + 4);
    uint32_t C = load_be32(in + 8);
    uint32_t D = load_be32(in + 12);
    uint32_t E = load_be32(in + 16);
    uint32_t F = load_be32(in + 20);
    uint32_t G = load_be32(in + 24);
    uint32_t H = load_be32(in + 28);

    for (size_t r = 0; r < 64; r += 8) {
        shacal2_rev(B, C, D, &E, F, G, H, &A, ctx->rk[63 - r]);
        shacal2_rev(C, D, E, &F, G, H, A, &B, ctx->rk[62 - r]);
        shacal2_rev(D, E, F, &G, H, A, B, &C, ctx->rk[61 - r]);
        shacal2_rev(E, F, G, &H, A, B, C, &D, ctx->rk[60 - r]);
        shacal2_rev(F, G, H, &A, B, C, D, &E, ctx->rk[59 - r]);
        shacal2_rev(G, H, A, &B, C, D, E, &F, ctx->rk[58 - r]);
        shacal2_rev(H, A, B, &C, D, E, F, &G, ctx->rk[57 - r]);
        shacal2_rev(A, B, C, &D, E, F, G, &H, ctx->rk[56 - r]);
    }

    store_be32(out, A);
    store_be32(out + 4, B);
    store_be32(out + 8, C);
    store_be32(out + 12, D);
    store_be32(out + 16, E);
    store_be32(out + 20, F);
    store_be32(out + 24, G);
    store_be32(out + 28, H);
}

void shacal2_cbc_encrypt(const shacal2_ctx *ctx,
                         const uint8_t *iv,
                         const uint8_t *in,
                         uint8_t *out,
                         size_t len)
{
    uint8_t prev[SHACAL2_BLOCK_SIZE];
    uint8_t block[SHACAL2_BLOCK_SIZE];
    size_t i;
    int j;

    memcpy(prev, iv, SHACAL2_BLOCK_SIZE);

    for (i = 0; i < len; i += SHACAL2_BLOCK_SIZE) {
        for (j = 0; j < SHACAL2_BLOCK_SIZE; j++) {
            block[j] = in[i + (size_t)j] ^ prev[j];
        }
        shacal2_encrypt_block(ctx, block, &out[i]);
        memcpy(prev, &out[i], SHACAL2_BLOCK_SIZE);
    }
}

void shacal2_cbc_decrypt(const shacal2_ctx *ctx,
                         const uint8_t *iv,
                         const uint8_t *in,
                         uint8_t *out,
                         size_t len)
{
    uint8_t prev[SHACAL2_BLOCK_SIZE];
    uint8_t temp[SHACAL2_BLOCK_SIZE];
    uint8_t block[SHACAL2_BLOCK_SIZE];
    size_t i;
    int j;

    memcpy(prev, iv, SHACAL2_BLOCK_SIZE);

    for (i = 0; i < len; i += SHACAL2_BLOCK_SIZE) {
        memcpy(temp, &in[i], SHACAL2_BLOCK_SIZE);
        shacal2_decrypt_block(ctx, &in[i], block);
        for (j = 0; j < SHACAL2_BLOCK_SIZE; j++) {
            out[i + (size_t)j] = block[j] ^ prev[j];
        }
        memcpy(prev, temp, SHACAL2_BLOCK_SIZE);
    }
}
