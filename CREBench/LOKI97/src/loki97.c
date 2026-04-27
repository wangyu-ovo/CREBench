/*
 * Adapted for CREBench from the public LOKI97 reference implementations.
 *
 * Credits:
 *   LOKI97 was written by Lawrie Brown, Josef Pieprzyk, and Jennifer Seberry.
 *   Copyright (c) 1998 by Lawrie Brown and ITRACE (UNSW).
 *   All rights reserved.
 */

#include "loki97.h"

#include <string.h>

#define LOKI97_ROUNDS 16
#define LOKI97_NUM_SUBKEYS (3 * LOKI97_ROUNDS)

#define S1_SIZE 0x2000
#define S2_SIZE 0x0800

static uint8_t s1[S1_SIZE];
static uint8_t s2[S2_SIZE];
static loki97_u64 perm_p[0x100];
static int loki97_init_done = 0;

#ifdef CONSTXOR_LOKI97_TABLES
#include "constxor_tables.h"
#define LOKI97_MAGIC_TABLE (constxor_loki97_magic())
#else
static const uint32_t loki97_magic[4] = {0x2911U, 0x0AA7U, 0x9E3779B9U, 0x7F4A7C15U};
#define LOKI97_MAGIC_TABLE (loki97_magic)
#endif

#define LOKI97_S1_GEN_VALUE ((int)LOKI97_MAGIC_TABLE[0])
#define LOKI97_S2_GEN_VALUE ((int)LOKI97_MAGIC_TABLE[1])
#define LOKI97_DELTA_VALUE ((loki97_u64){LOKI97_MAGIC_TABLE[2], LOKI97_MAGIC_TABLE[3]})

static int mult(int a, int b, int g, int n)
{
    int p = 0;
    while (b != 0) {
        if ((b & 0x01) != 0) {
            p ^= a;
        }
        a <<= 1;
        if (a >= n) {
            a ^= g;
        }
        b >>= 1;
    }
    return p;
}

static int exp3(int b, int g, int n)
{
    int r = b;
    if (b == 0) {
        return 0;
    }
    b = mult(r, b, g, n);
    r = mult(r, b, g, n);
    return r;
}

static void loki97_init_tables(void)
{
    if (loki97_init_done) {
        return;
    }

    const int s1_mask = S1_SIZE - 1;
    const int s2_mask = S2_SIZE - 1;

    for (int i = 0; i < S1_SIZE; i++) {
        int b = i ^ s1_mask;
        s1[i] = (uint8_t)exp3(b, LOKI97_S1_GEN_VALUE, S1_SIZE);
    }

    for (int i = 0; i < S2_SIZE; i++) {
        int b = i ^ s2_mask;
        s2[i] = (uint8_t)exp3(b, LOKI97_S2_GEN_VALUE, S2_SIZE);
    }

    for (int i = 0; i < 0x100; i++) {
        uint32_t pval = 0;
        for (int j = 0, k = 7; j < 4; j++, k += 8) {
            pval |= ((uint32_t)((i >> j) & 0x1) << k);
        }
        perm_p[i].r = pval;
        pval = 0;
        for (int j = 4, k = 7; j < 8; j++, k += 8) {
            pval |= ((uint32_t)((i >> j) & 0x1) << k);
        }
        perm_p[i].l = pval;
    }

    loki97_init_done = 1;
}

static loki97_u64 add64(loki97_u64 a, loki97_u64 b)
{
    loki97_u64 sum;
    sum.r = a.r + b.r;
    sum.l = a.l + b.l;
    if (sum.r < b.r) {
        sum.l++;
    }
    return sum;
}

static loki97_u64 sub64(loki97_u64 a, loki97_u64 b)
{
    loki97_u64 diff;
    diff.r = a.r - b.r;
    diff.l = a.l - b.l;
    if (diff.r > a.r) {
        diff.l--;
    }
    return diff;
}

static loki97_u64 xor64(loki97_u64 a, loki97_u64 b)
{
    loki97_u64 out;
    out.l = a.l ^ b.l;
    out.r = a.r ^ b.r;
    return out;
}

static loki97_u64 load_u64(const uint8_t *in)
{
    loki97_u64 v;
    v.l = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
    v.r = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) | ((uint32_t)in[6] << 8) | (uint32_t)in[7];
    return v;
}

static void store_u64(uint8_t *out, loki97_u64 v)
{
    out[0] = (uint8_t)(v.l >> 24);
    out[1] = (uint8_t)(v.l >> 16);
    out[2] = (uint8_t)(v.l >> 8);
    out[3] = (uint8_t)v.l;
    out[4] = (uint8_t)(v.r >> 24);
    out[5] = (uint8_t)(v.r >> 16);
    out[6] = (uint8_t)(v.r >> 8);
    out[7] = (uint8_t)v.r;
}

static loki97_u64 f_func(loki97_u64 A, loki97_u64 B)
{
    loki97_u64 d, e, f;
    uint32_t s;

    d.l = (A.l & ~B.r) | (A.r & B.r);
    d.r = (A.r & ~B.r) | (A.l & B.r);

    s = s1[((d.l >> 24) | (d.r << 8)) & 0x1FFF];
    e.l = perm_p[s].l >> 7;
    e.r = perm_p[s].r >> 7;
    s = s2[(d.l >> 16) & 0x7FF];
    e.l |= perm_p[s].l >> 6;
    e.r |= perm_p[s].r >> 6;
    s = s1[(d.l >> 8) & 0x1FFF];
    e.l |= perm_p[s].l >> 5;
    e.r |= perm_p[s].r >> 5;
    s = s2[d.l & 0x7FF];
    e.l |= perm_p[s].l >> 4;
    e.r |= perm_p[s].r >> 4;
    s = s2[((d.r >> 24) | (d.l << 8)) & 0x7FF];
    e.l |= perm_p[s].l >> 3;
    e.r |= perm_p[s].r >> 3;
    s = s1[(d.r >> 16) & 0x1FFF];
    e.l |= perm_p[s].l >> 2;
    e.r |= perm_p[s].r >> 2;
    s = s2[(d.r >> 8) & 0x7FF];
    e.l |= perm_p[s].l >> 1;
    e.r |= perm_p[s].r >> 1;
    s = s1[d.r & 0x1FFF];
    e.l |= perm_p[s].l;
    e.r |= perm_p[s].r;

    f.l = ((uint32_t)s2[((e.l >> 24) & 0xFF) | ((B.l >> 21) & 0x700)] << 24)
        | ((uint32_t)s2[((e.l >> 16) & 0xFF) | ((B.l >> 18) & 0x700)] << 16)
        | ((uint32_t)s1[((e.l >> 8) & 0xFF) | ((B.l >> 13) & 0x1F00)] << 8)
        | ((uint32_t)s1[(e.l & 0xFF) | ((B.l >> 8) & 0x1F00)]);

    f.r = ((uint32_t)s2[((e.r >> 24) & 0xFF) | ((B.l >> 5) & 0x700)] << 24)
        | ((uint32_t)s2[((e.r >> 16) & 0xFF) | ((B.l >> 2) & 0x700)] << 16)
        | ((uint32_t)s1[((e.r >> 8) & 0xFF) | ((B.l << 3) & 0x1F00)] << 8)
        | ((uint32_t)s1[(e.r & 0xFF) | ((B.l << 8) & 0x1F00)]);

    return f;
}

int loki97_set_key(loki97_ctx *ctx, const uint8_t *key, size_t key_len)
{
    if (!ctx || !key) {
        return -1;
    }
    if (key_len != 16 && key_len != 24 && key_len != 32) {
        return -1;
    }

    loki97_init_tables();

    loki97_u64 k4 = load_u64(key);
    loki97_u64 k3 = load_u64(key + 8);
    loki97_u64 k2;
    loki97_u64 k1;

    if (key_len == 16) {
        k2 = f_func(k3, k4);
        k1 = f_func(k4, k3);
    } else {
        k2 = load_u64(key + 16);
        if (key_len == 24) {
            k1 = f_func(k4, k3);
        } else {
            k1 = load_u64(key + 24);
        }
    }

    loki97_u64 deltan = LOKI97_DELTA_VALUE;
    for (int i = 0; i < LOKI97_NUM_SUBKEYS; i++) {
        loki97_u64 t1 = add64(k1, k3);
        loki97_u64 t2 = add64(t1, deltan);
        loki97_u64 f_out = f_func(t2, k2);
        ctx->sk[i] = xor64(k4, f_out);
        k4 = k3;
        k3 = k2;
        k2 = k1;
        k1 = ctx->sk[i];
        deltan = add64(deltan, LOKI97_DELTA_VALUE);
    }

    return 0;
}

void loki97_encrypt_block(const loki97_ctx *ctx, const uint8_t *in, uint8_t *out)
{
    loki97_u64 L = load_u64(in);
    loki97_u64 R = load_u64(in + 8);
    loki97_u64 nR;
    loki97_u64 f_out;
    int k = 0;

    for (int i = 0; i < LOKI97_ROUNDS; i++) {
        nR = add64(R, ctx->sk[k++]);
        f_out = f_func(nR, ctx->sk[k++]);
        nR = add64(nR, ctx->sk[k++]);
        R = xor64(L, f_out);
        L = nR;
    }

    store_u64(out, R);
    store_u64(out + 8, L);
}

void loki97_decrypt_block(const loki97_ctx *ctx, const uint8_t *in, uint8_t *out)
{
    loki97_u64 L = load_u64(in);
    loki97_u64 R = load_u64(in + 8);
    loki97_u64 nR;
    loki97_u64 f_out;
    int k = LOKI97_NUM_SUBKEYS - 1;

    for (int i = 0; i < LOKI97_ROUNDS; i++) {
        nR = sub64(R, ctx->sk[k--]);
        f_out = f_func(nR, ctx->sk[k--]);
        nR = sub64(nR, ctx->sk[k--]);
        R = xor64(L, f_out);
        L = nR;
    }

    store_u64(out, R);
    store_u64(out + 8, L);
}

void loki97_cbc_encrypt(const loki97_ctx *ctx,
                        const uint8_t *iv,
                        const uint8_t *in,
                        uint8_t *out,
                        size_t len)
{
    uint8_t prev[LOKI97_BLOCK_SIZE];
    memcpy(prev, iv, sizeof(prev));

    for (size_t offset = 0; offset < len; offset += LOKI97_BLOCK_SIZE) {
        uint8_t block[LOKI97_BLOCK_SIZE];
        for (size_t i = 0; i < LOKI97_BLOCK_SIZE; i++) {
            block[i] = (uint8_t)(in[offset + i] ^ prev[i]);
        }
        loki97_encrypt_block(ctx, block, out + offset);
        memcpy(prev, out + offset, LOKI97_BLOCK_SIZE);
    }
}

void loki97_cbc_decrypt(const loki97_ctx *ctx,
                        const uint8_t *iv,
                        const uint8_t *in,
                        uint8_t *out,
                        size_t len)
{
    uint8_t prev[LOKI97_BLOCK_SIZE];
    memcpy(prev, iv, sizeof(prev));

    for (size_t offset = 0; offset < len; offset += LOKI97_BLOCK_SIZE) {
        uint8_t block[LOKI97_BLOCK_SIZE];
        loki97_decrypt_block(ctx, in + offset, block);
        for (size_t i = 0; i < LOKI97_BLOCK_SIZE; i++) {
            out[offset + i] = (uint8_t)(block[i] ^ prev[i]);
        }
        memcpy(prev, in + offset, LOKI97_BLOCK_SIZE);
    }
}
