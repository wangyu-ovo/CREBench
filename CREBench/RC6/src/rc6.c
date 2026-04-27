/*
 * Adapted from Crypto++.
 *
 * Copyright (c) 1995-2024 by Wei Dai. All rights reserved.
 */

#include "rc6.h"

#include <string.h>

#ifdef CONSTXOR_RC6_TABLES
#include "constxor_tables.h"
#define RC6_MAGIC_TABLE (constxor_rc6_magic())
#else
static const uint32_t rc6_magic[2] = {
    0xB7E15163UL,
    0x9E3779B9UL
};
#define RC6_MAGIC_TABLE (rc6_magic)
#endif

#define RC6_P32 (RC6_MAGIC_TABLE[0])
#define RC6_Q32 (RC6_MAGIC_TABLE[1])

static uint32_t rotl32(uint32_t x, uint32_t r)
{
    r &= 31U;
    return (x << r) | (x >> (32U - r));
}

static uint32_t rotr32(uint32_t x, uint32_t r)
{
    r &= 31U;
    return (x >> r) | (x << (32U - r));
}

static uint32_t load_le32(const uint8_t *in)
{
    return (uint32_t)in[0]
        | ((uint32_t)in[1] << 8)
        | ((uint32_t)in[2] << 16)
        | ((uint32_t)in[3] << 24);
}

static void store_le32(uint8_t *out, uint32_t v)
{
    out[0] = (uint8_t)(v & 0xFFU);
    out[1] = (uint8_t)((v >> 8) & 0xFFU);
    out[2] = (uint8_t)((v >> 16) & 0xFFU);
    out[3] = (uint8_t)((v >> 24) & 0xFFU);
}

int rc6_set_key(rc6_ctx *ctx, const uint8_t *key, size_t key_len)
{
    uint32_t L[RC6_MAX_KEY_SIZE / 4];
    const unsigned int t = 2 * (RC6_ROUNDS + 2);
    unsigned int c;
    unsigned int i;
    uint32_t A = 0;
    uint32_t B = 0;
    unsigned int n;

    if (!ctx || !key) {
        return -1;
    }
    if (key_len != 16 && key_len != 24 && key_len != 32) {
        return -1;
    }

    memset(L, 0, sizeof(L));
    for (i = 0; i < key_len; i++) {
        L[i / 4] |= ((uint32_t)key[i] << (8U * (i % 4)));
    }

    c = (unsigned int)((key_len + 3) / 4);
    if (c == 0) {
        c = 1;
    }

    ctx->s[0] = RC6_P32;
    for (i = 1; i < t; i++) {
        ctx->s[i] = ctx->s[i - 1] + RC6_Q32;
    }

    n = 3 * ((t > c) ? t : c);
    for (i = 0; i < n; i++) {
        A = ctx->s[i % t] = rotl32(ctx->s[i % t] + A + B, 3);
        B = L[i % c] = rotl32(L[i % c] + A + B, A + B);
    }

    ctx->rounds = RC6_ROUNDS;
    return 0;
}

void rc6_encrypt_block(const rc6_ctx *ctx, const uint8_t *in, uint8_t *out)
{
    uint32_t a = load_le32(in);
    uint32_t b = load_le32(in + 4);
    uint32_t c = load_le32(in + 8);
    uint32_t d = load_le32(in + 12);
    uint32_t t, u;
    unsigned int i;
    const uint32_t *s = ctx->s;

    b += s[0];
    d += s[1];

    for (i = 0; i < ctx->rounds; i++) {
        t = rotl32(b * (2U * b + 1U), 5);
        u = rotl32(d * (2U * d + 1U), 5);
        a = rotl32(a ^ t, u) + s[2 * i + 2];
        c = rotl32(c ^ u, t) + s[2 * i + 3];

        t = a; a = b; b = c; c = d; d = t;
    }

    a += s[2 * ctx->rounds + 2];
    c += s[2 * ctx->rounds + 3];

    store_le32(out, a);
    store_le32(out + 4, b);
    store_le32(out + 8, c);
    store_le32(out + 12, d);
}

void rc6_decrypt_block(const rc6_ctx *ctx, const uint8_t *in, uint8_t *out)
{
    uint32_t a = load_le32(in);
    uint32_t b = load_le32(in + 4);
    uint32_t c = load_le32(in + 8);
    uint32_t d = load_le32(in + 12);
    uint32_t t, u;
    int i;
    const uint32_t *s = ctx->s;

    c -= s[2 * ctx->rounds + 3];
    a -= s[2 * ctx->rounds + 2];

    for (i = (int)ctx->rounds - 1; i >= 0; i--) {
        t = a; a = d; d = c; c = b; b = t;
        u = rotl32(d * (2U * d + 1U), 5);
        t = rotl32(b * (2U * b + 1U), 5);
        c = rotr32(c - s[2 * i + 3], t) ^ u;
        a = rotr32(a - s[2 * i + 2], u) ^ t;
    }

    d -= s[1];
    b -= s[0];

    store_le32(out, a);
    store_le32(out + 4, b);
    store_le32(out + 8, c);
    store_le32(out + 12, d);
}

void rc6_cbc_encrypt(const rc6_ctx *ctx,
                     const uint8_t *iv,
                     const uint8_t *in,
                     uint8_t *out,
                     size_t len)
{
    uint8_t prev[RC6_BLOCK_SIZE];

    memcpy(prev, iv, sizeof(prev));

    for (size_t offset = 0; offset < len; offset += RC6_BLOCK_SIZE) {
        uint8_t block[RC6_BLOCK_SIZE];
        for (size_t i = 0; i < RC6_BLOCK_SIZE; i++) {
            block[i] = (uint8_t)(in[offset + i] ^ prev[i]);
        }
        rc6_encrypt_block(ctx, block, out + offset);
        memcpy(prev, out + offset, RC6_BLOCK_SIZE);
    }
}

void rc6_cbc_decrypt(const rc6_ctx *ctx,
                     const uint8_t *iv,
                     const uint8_t *in,
                     uint8_t *out,
                     size_t len)
{
    uint8_t prev[RC6_BLOCK_SIZE];

    memcpy(prev, iv, sizeof(prev));

    for (size_t offset = 0; offset < len; offset += RC6_BLOCK_SIZE) {
        uint8_t block[RC6_BLOCK_SIZE];
        rc6_decrypt_block(ctx, in + offset, block);
        for (size_t i = 0; i < RC6_BLOCK_SIZE; i++) {
            out[offset + i] = (uint8_t)(block[i] ^ prev[i]);
        }
        memcpy(prev, in + offset, RC6_BLOCK_SIZE);
    }
}
