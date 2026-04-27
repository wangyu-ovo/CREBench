/*
 * Adapted for CryptoRevBench from public NOEKEON references.
 *
 * Reference attributions:
 *   - NESSIE NOEKEON reference implementation (NoekeonIndirectRef.c):
 *       Authors: Joan Daemen, Michael Peeters, Vincent Rijmen, Gilles Van Assche
 *       Written by Michael Peeters
 *   - Botan implementation:
 *       (C) 1999-2008 Jack Lloyd
 *       Botan is released under the Simplified BSD License
 */

#include "noekeon.h"

#include <string.h>

#ifdef CONSTXOR_NOEKEON_TABLES
#include "constxor_tables.h"
#define NOEKEON_RC_TABLE (constxor_noekeon_rc())
#else
static const uint8_t rc_table[17] = {
    0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4
};
#define NOEKEON_RC_TABLE (rc_table)
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

static inline uint32_t rotl32(uint32_t x, uint32_t n)
{
    n &= 31;
    return (x << n) | (x >> ((32 - n) & 31));
}

static inline uint32_t rotr32(uint32_t x, uint32_t n)
{
    n &= 31;
    return (x >> n) | (x << ((32 - n) & 31));
}

static void theta_null(uint32_t *a)
{
    uint32_t tmp = a[0] ^ a[2];
    tmp ^= rotl32(tmp, 8) ^ rotr32(tmp, 8);
    a[1] ^= tmp;
    a[3] ^= tmp;

    tmp = a[1] ^ a[3];
    tmp ^= rotl32(tmp, 8) ^ rotr32(tmp, 8);
    a[0] ^= tmp;
    a[2] ^= tmp;
}

static void theta_key(uint32_t *a, const uint32_t *k)
{
    uint32_t tmp = a[0] ^ a[2];
    tmp ^= rotl32(tmp, 8) ^ rotr32(tmp, 8);
    a[1] ^= tmp;
    a[3] ^= tmp;

    a[0] ^= k[0];
    a[1] ^= k[1];
    a[2] ^= k[2];
    a[3] ^= k[3];

    tmp = a[1] ^ a[3];
    tmp ^= rotl32(tmp, 8) ^ rotr32(tmp, 8);
    a[0] ^= tmp;
    a[2] ^= tmp;
}

static void gamma_layer(uint32_t *a)
{
    a[1] ^= ~(a[2] | a[3]);
    a[0] ^= a[2] & a[1];

    uint32_t tmp = a[3];
    a[3] = a[0];
    a[0] = tmp;

    a[2] ^= a[0] ^ a[1] ^ a[3];

    a[1] ^= ~(a[2] | a[3]);
    a[0] ^= a[2] & a[1];
}

static void pi1_layer(uint32_t *a)
{
    a[1] = rotl32(a[1], 1);
    a[2] = rotl32(a[2], 5);
    a[3] = rotl32(a[3], 2);
}

static void pi2_layer(uint32_t *a)
{
    a[1] = rotr32(a[1], 1);
    a[2] = rotr32(a[2], 5);
    a[3] = rotr32(a[3], 2);
}

int noekeon_set_key(noekeon_ctx *ctx, const uint8_t *key, size_t key_len)
{
    if (!ctx || !key || key_len != NOEKEON_KEY_SIZE) {
        return -1;
    }

    uint32_t a[4];
    a[0] = load_be32(key);
    a[1] = load_be32(key + 4);
    a[2] = load_be32(key + 8);
    a[3] = load_be32(key + 12);

    for (size_t i = 0; i < 16; i++) {
        a[0] ^= NOEKEON_RC_TABLE[i];
        theta_null(a);
        pi1_layer(a);
        gamma_layer(a);
        pi2_layer(a);
    }

    a[0] ^= NOEKEON_RC_TABLE[16];
    ctx->dk[0] = a[0];
    ctx->dk[1] = a[1];
    ctx->dk[2] = a[2];
    ctx->dk[3] = a[3];

    theta_null(a);
    ctx->k[0] = a[0];
    ctx->k[1] = a[1];
    ctx->k[2] = a[2];
    ctx->k[3] = a[3];

    return 0;
}

void noekeon_encrypt_block(const noekeon_ctx *ctx, const uint8_t *in, uint8_t *out)
{
    uint32_t a[4];
    a[0] = load_be32(in);
    a[1] = load_be32(in + 4);
    a[2] = load_be32(in + 8);
    a[3] = load_be32(in + 12);

    for (size_t i = 0; i < 16; i++) {
        a[0] ^= NOEKEON_RC_TABLE[i];
        theta_key(a, ctx->k);
        pi1_layer(a);
        gamma_layer(a);
        pi2_layer(a);
    }

    a[0] ^= NOEKEON_RC_TABLE[16];
    theta_key(a, ctx->k);

    store_be32(out, a[0]);
    store_be32(out + 4, a[1]);
    store_be32(out + 8, a[2]);
    store_be32(out + 12, a[3]);
}

void noekeon_decrypt_block(const noekeon_ctx *ctx, const uint8_t *in, uint8_t *out)
{
    uint32_t a[4];
    a[0] = load_be32(in);
    a[1] = load_be32(in + 4);
    a[2] = load_be32(in + 8);
    a[3] = load_be32(in + 12);

    for (size_t i = 16; i > 0; i--) {
        theta_key(a, ctx->dk);
        a[0] ^= NOEKEON_RC_TABLE[i];
        pi1_layer(a);
        gamma_layer(a);
        pi2_layer(a);
    }

    theta_key(a, ctx->dk);
    a[0] ^= NOEKEON_RC_TABLE[0];

    store_be32(out, a[0]);
    store_be32(out + 4, a[1]);
    store_be32(out + 8, a[2]);
    store_be32(out + 12, a[3]);
}

void noekeon_cbc_encrypt(const noekeon_ctx *ctx,
                         const uint8_t *iv,
                         const uint8_t *in,
                         uint8_t *out,
                         size_t len)
{
    uint8_t prev[NOEKEON_BLOCK_SIZE];
    uint8_t block[NOEKEON_BLOCK_SIZE];
    size_t i;
    int j;

    memcpy(prev, iv, NOEKEON_BLOCK_SIZE);

    for (i = 0; i < len; i += NOEKEON_BLOCK_SIZE) {
        for (j = 0; j < NOEKEON_BLOCK_SIZE; j++) {
            block[j] = in[i + (size_t)j] ^ prev[j];
        }
        noekeon_encrypt_block(ctx, block, &out[i]);
        memcpy(prev, &out[i], NOEKEON_BLOCK_SIZE);
    }
}

void noekeon_cbc_decrypt(const noekeon_ctx *ctx,
                         const uint8_t *iv,
                         const uint8_t *in,
                         uint8_t *out,
                         size_t len)
{
    uint8_t prev[NOEKEON_BLOCK_SIZE];
    uint8_t temp[NOEKEON_BLOCK_SIZE];
    uint8_t block[NOEKEON_BLOCK_SIZE];
    size_t i;
    int j;

    memcpy(prev, iv, NOEKEON_BLOCK_SIZE);

    for (i = 0; i < len; i += NOEKEON_BLOCK_SIZE) {
        memcpy(temp, &in[i], NOEKEON_BLOCK_SIZE);
        noekeon_decrypt_block(ctx, &in[i], block);
        for (j = 0; j < NOEKEON_BLOCK_SIZE; j++) {
            out[i + (size_t)j] = block[j] ^ prev[j];
        }
        memcpy(prev, temp, NOEKEON_BLOCK_SIZE);
    }
}
