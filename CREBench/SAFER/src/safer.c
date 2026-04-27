/*
 * Adapted from Crypto++.
 *
 * Copyright (c) 1995-2024 by Wei Dai. All rights reserved.
 */

#include "safer.h"

#include <string.h>

#ifdef CONSTXOR_SAFER_TABLES
#include "constxor_tables.h"
#define SAFER_EBOX_TABLE (constxor_safer_ebox())
#define SAFER_LBOX_TABLE (constxor_safer_lbox())
#else
static const uint8_t safer_ebox[256] = {
    1,  45, 226, 147, 190,  69,  21, 174, 120,   3, 135, 164, 184,  56, 207,  63,
    8, 103,   9, 148, 235,  38, 168, 107, 189,  24,  52,  27, 187, 191, 114, 247,
   64,  53,  72, 156,  81,  47,  59,  85, 227, 192, 159, 216, 211, 243, 141, 177,
  255, 167,  62, 220, 134, 119, 215, 166,  17, 251, 244, 186, 146, 145, 100, 131,
  241,  51, 239, 218,  44, 181, 178,  43, 136, 209, 153, 203, 140, 132,  29,  20,
  129, 151, 113, 202,  95, 163, 139,  87,  60, 130, 196,  82,  92,  28, 232, 160,
    4, 180, 133,  74, 246,  19,  84, 182, 223,  12,  26, 142, 222, 224,  57, 252,
   32, 155,  36,  78, 169, 152, 158, 171, 242,  96, 208, 108, 234, 250, 199, 217,
    0, 212,  31, 110,  67, 188, 236,  83, 137, 254, 122,  93,  73, 201,  50, 194,
  249, 154, 248, 109,  22, 219,  89, 150,  68, 233, 205, 230,  70,  66, 143,  10,
  193, 204, 185, 101, 176, 210, 198, 172,  30,  65,  98,  41,  46,  14, 116,  80,
    2,  90, 195,  37, 123, 138,  42,  91, 240,   6,  13,  71, 111, 112, 157, 126,
   16, 206,  18,  39, 213,  76,  79, 214, 121,  48, 104,  54, 117, 125, 228, 237,
  128, 106, 144,  55, 162,  94, 118, 170, 197, 127,  61, 175, 165, 229,  25,  97,
  253,  77, 124, 183,  11, 238, 173,  75,  34, 245, 231, 115,  35,  33, 200,   5,
  225, 102, 221, 179,  88, 105,  99,  86,  15, 161,  49, 149,  23,   7,  58,  40
};

static const uint8_t safer_lbox[256] = {
  128,   0, 176,   9,  96, 239, 185, 253,  16,  18, 159, 228, 105, 186, 173, 248,
  192,  56, 194, 101,  79,   6, 148, 252,  25, 222, 106,  27,  93,  78, 168, 130,
  112, 237, 232, 236, 114, 179,  21, 195, 255, 171, 182,  71,  68,   1, 172,  37,
  201, 250, 142,  65,  26,  33, 203, 211,  13, 110, 254,  38,  88, 218,  50,  15,
   32, 169, 157, 132, 152,   5, 156, 187,  34, 140,  99, 231, 197, 225, 115, 198,
  175,  36,  91, 135, 102,  39, 247,  87, 244, 150, 177, 183,  92, 139, 213,  84,
  121, 223, 170, 246,  62, 163, 241,  17, 202, 245, 209,  23, 123, 147, 131, 188,
  189,  82,  30, 235, 174, 204, 214,  53,   8, 200, 138, 180, 226, 205, 191, 217,
  208,  80,  89,  63,  77,  98,  52,  10,  72, 136, 181,  86,  76,  46, 107, 158,
  210,  61,  60,   3,  19, 251, 151,  81, 117,  74, 145, 113,  35, 190, 118,  42,
   95, 249, 212,  85,  11, 220,  55,  49,  22, 116, 215, 119, 167, 230,   7, 219,
  164,  47,  70, 243,  97,  69, 103, 227,  12, 162,  59,  28, 133,  24,   4,  29,
   41, 160, 143, 178,  90, 216, 166, 126, 238, 141,  83,  75, 161, 154, 193,  14,
  122,  73, 165,  44, 129, 196, 199,  54,  43, 127,  67, 149,  51, 242, 108, 104,
  109, 240,   2,  40, 206, 221, 155, 234,  94, 153, 124,  20, 134, 207, 229,  66,
  184,  64, 120,  45,  58, 233, 100,  31, 146, 144, 125,  57, 111, 224, 137,  48
};
#define SAFER_EBOX_TABLE (safer_ebox)
#define SAFER_LBOX_TABLE (safer_lbox)
#endif

static uint8_t rol8(uint8_t x, unsigned int n)
{
    return (uint8_t)((x << n) | (x >> (8U - n)));
}

static uint8_t exp_byte(uint8_t x)
{
    return SAFER_EBOX_TABLE[x];
}

static uint8_t log_byte(uint8_t x)
{
    return SAFER_LBOX_TABLE[x];
}

static void pht(uint8_t *x, uint8_t *y)
{
    *y = (uint8_t)(*y + *x);
    *x = (uint8_t)(*x + *y);
}

static void ipht(uint8_t *x, uint8_t *y)
{
    *x = (uint8_t)(*x - *y);
    *y = (uint8_t)(*y - *x);
}

static void safer_expand_userkey(const uint8_t *userkey_1,
                                 const uint8_t *userkey_2,
                                 unsigned int rounds,
                                 int strengthened,
                                 uint8_t *key)
{
    uint8_t ka[SAFER_BLOCK_SIZE + 1];
    uint8_t kb[SAFER_BLOCK_SIZE + 1];
    unsigned int i, j, k;

    if (rounds > SAFER_MAX_ROUNDS) {
        rounds = SAFER_MAX_ROUNDS;
    }

    *key++ = (uint8_t)rounds;
    ka[SAFER_BLOCK_SIZE] = 0;
    kb[SAFER_BLOCK_SIZE] = 0;

    k = 0;
    for (j = 0; j < SAFER_BLOCK_SIZE; j++) {
        ka[j] = rol8(userkey_1[j], 5);
        ka[SAFER_BLOCK_SIZE] ^= ka[j];
        kb[j] = *key++ = userkey_2[j];
        kb[SAFER_BLOCK_SIZE] ^= kb[j];
    }

    for (i = 1; i <= rounds; i++) {
        for (j = 0; j < SAFER_BLOCK_SIZE + 1; j++) {
            ka[j] = rol8(ka[j], 6);
            kb[j] = rol8(kb[j], 6);
        }

        if (strengthened) {
            k = (unsigned int)(2 * i - 1);
            while (k >= (SAFER_BLOCK_SIZE + 1)) {
                k -= (SAFER_BLOCK_SIZE + 1);
            }
        }

        for (j = 0; j < SAFER_BLOCK_SIZE; j++) {
            uint8_t rnd = exp_byte(exp_byte((uint8_t)((18 * i + j + 1) & 0xFF)));
            if (strengthened) {
                *key++ = (uint8_t)(ka[k] + rnd);
                if (++k == (SAFER_BLOCK_SIZE + 1)) {
                    k = 0;
                }
            } else {
                *key++ = (uint8_t)(ka[j] + rnd);
            }
        }

        if (strengthened) {
            k = (unsigned int)(2 * i);
            while (k >= (SAFER_BLOCK_SIZE + 1)) {
                k -= (SAFER_BLOCK_SIZE + 1);
            }
        }

        for (j = 0; j < SAFER_BLOCK_SIZE; j++) {
            uint8_t rnd = exp_byte(exp_byte((uint8_t)((18 * i + j + 10) & 0xFF)));
            if (strengthened) {
                *key++ = (uint8_t)(kb[k] + rnd);
                if (++k == (SAFER_BLOCK_SIZE + 1)) {
                    k = 0;
                }
            } else {
                *key++ = (uint8_t)(kb[j] + rnd);
            }
        }
    }
}

static int safer_set_key_internal(safer_ctx *ctx,
                                  const uint8_t *key,
                                  size_t key_len,
                                  int strengthened)
{
    unsigned int rounds;

    if (!ctx || !key) {
        return -1;
    }
    if (key_len != 8 && key_len != 16) {
        return -1;
    }

    if (key_len == 8) {
        rounds = strengthened ? SAFER_SK64_DEFAULT_ROUNDS : SAFER_K64_DEFAULT_ROUNDS;
        safer_expand_userkey(key, key, rounds, strengthened, ctx->key);
    } else {
        rounds = strengthened ? SAFER_SK128_DEFAULT_ROUNDS : SAFER_K128_DEFAULT_ROUNDS;
        safer_expand_userkey(key, key + 8, rounds, strengthened, ctx->key);
    }

    return 0;
}

int safer_set_key(safer_ctx *ctx, const uint8_t *key, size_t key_len)
{
    return safer_set_key_internal(ctx, key, key_len, 0);
}

int safer_set_key_sk(safer_ctx *ctx, const uint8_t *key, size_t key_len)
{
    return safer_set_key_internal(ctx, key, key_len, 1);
}

void safer_encrypt_block(const safer_ctx *ctx, const uint8_t *in, uint8_t *out)
{
    uint8_t a, b, c, d, e, f, g, h, t;
    unsigned int round;
    const uint8_t *key = ctx->key;

    a = in[0]; b = in[1]; c = in[2]; d = in[3];
    e = in[4]; f = in[5]; g = in[6]; h = in[7];

    round = key[0];
    if (round > SAFER_MAX_ROUNDS) {
        round = SAFER_MAX_ROUNDS;
    }
    key++;

    while (round-- > 0) {
        a ^= *key++; b = (uint8_t)(b + *key++);
        c = (uint8_t)(c + *key++); d ^= *key++;
        e ^= *key++; f = (uint8_t)(f + *key++);
        g = (uint8_t)(g + *key++); h ^= *key++;

        a = (uint8_t)(exp_byte(a) + *key++);
        b = (uint8_t)(log_byte(b) ^ *key++);
        c = (uint8_t)(log_byte(c) ^ *key++);
        d = (uint8_t)(exp_byte(d) + *key++);
        e = (uint8_t)(exp_byte(e) + *key++);
        f = (uint8_t)(log_byte(f) ^ *key++);
        g = (uint8_t)(log_byte(g) ^ *key++);
        h = (uint8_t)(exp_byte(h) + *key++);

        pht(&a, &b); pht(&c, &d); pht(&e, &f); pht(&g, &h);
        pht(&a, &c); pht(&e, &g); pht(&b, &d); pht(&f, &h);
        pht(&a, &e); pht(&b, &f); pht(&c, &g); pht(&d, &h);

        t = b; b = e; e = c; c = t;
        t = d; d = f; f = g; g = t;
    }

    a ^= *key++; b = (uint8_t)(b + *key++);
    c = (uint8_t)(c + *key++); d ^= *key++;
    e ^= *key++; f = (uint8_t)(f + *key++);
    g = (uint8_t)(g + *key++); h ^= *key++;

    out[0] = a; out[1] = b; out[2] = c; out[3] = d;
    out[4] = e; out[5] = f; out[6] = g; out[7] = h;
}

void safer_decrypt_block(const safer_ctx *ctx, const uint8_t *in, uint8_t *out)
{
    uint8_t a, b, c, d, e, f, g, h, t;
    unsigned int round;
    const uint8_t *key = ctx->key;

    a = in[0]; b = in[1]; c = in[2]; d = in[3];
    e = in[4]; f = in[5]; g = in[6]; h = in[7];

    round = key[0];
    if (round > SAFER_MAX_ROUNDS) {
        round = SAFER_MAX_ROUNDS;
    }

    key += SAFER_BLOCK_SIZE * (1 + 2 * round);

    h ^= *key; g = (uint8_t)(g - *--key);
    f = (uint8_t)(f - *--key); e ^= *--key;
    d ^= *--key; c = (uint8_t)(c - *--key);
    b = (uint8_t)(b - *--key); a ^= *--key;

    while (round-- > 0) {
        t = e; e = b; b = c; c = t;
        t = f; f = d; d = g; g = t;

        ipht(&a, &e); ipht(&b, &f); ipht(&c, &g); ipht(&d, &h);
        ipht(&a, &c); ipht(&e, &g); ipht(&b, &d); ipht(&f, &h);
        ipht(&a, &b); ipht(&c, &d); ipht(&e, &f); ipht(&g, &h);

        h = (uint8_t)(h - *--key); g ^= *--key;
        f ^= *--key; e = (uint8_t)(e - *--key);
        d = (uint8_t)(d - *--key); c ^= *--key;
        b ^= *--key; a = (uint8_t)(a - *--key);

        h = (uint8_t)(log_byte(h) ^ *--key);
        g = (uint8_t)(exp_byte(g) - *--key);
        f = (uint8_t)(exp_byte(f) - *--key);
        e = (uint8_t)(log_byte(e) ^ *--key);
        d = (uint8_t)(log_byte(d) ^ *--key);
        c = (uint8_t)(exp_byte(c) - *--key);
        b = (uint8_t)(exp_byte(b) - *--key);
        a = (uint8_t)(log_byte(a) ^ *--key);
    }

    out[0] = a; out[1] = b; out[2] = c; out[3] = d;
    out[4] = e; out[5] = f; out[6] = g; out[7] = h;
}

void safer_cbc_encrypt(const safer_ctx *ctx,
                       const uint8_t *iv,
                       const uint8_t *in,
                       uint8_t *out,
                       size_t len)
{
    uint8_t prev[SAFER_BLOCK_SIZE];

    memcpy(prev, iv, sizeof(prev));

    for (size_t offset = 0; offset < len; offset += SAFER_BLOCK_SIZE) {
        uint8_t block[SAFER_BLOCK_SIZE];
        for (size_t i = 0; i < SAFER_BLOCK_SIZE; i++) {
            block[i] = (uint8_t)(in[offset + i] ^ prev[i]);
        }
        safer_encrypt_block(ctx, block, out + offset);
        memcpy(prev, out + offset, SAFER_BLOCK_SIZE);
    }
}

void safer_cbc_decrypt(const safer_ctx *ctx,
                       const uint8_t *iv,
                       const uint8_t *in,
                       uint8_t *out,
                       size_t len)
{
    uint8_t prev[SAFER_BLOCK_SIZE];

    memcpy(prev, iv, sizeof(prev));

    for (size_t offset = 0; offset < len; offset += SAFER_BLOCK_SIZE) {
        uint8_t block[SAFER_BLOCK_SIZE];
        safer_decrypt_block(ctx, in + offset, block);
        for (size_t i = 0; i < SAFER_BLOCK_SIZE; i++) {
            out[offset + i] = (uint8_t)(block[i] ^ prev[i]);
        }
        memcpy(prev, in + offset, SAFER_BLOCK_SIZE);
    }
}
