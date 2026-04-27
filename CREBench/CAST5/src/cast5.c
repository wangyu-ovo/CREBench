#include "cast5.h"

#include <string.h>

#include "cast5_sboxes.h"

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

static inline uint8_t u8a(uint32_t x) { return (uint8_t)(x >> 24); }
static inline uint8_t u8b(uint32_t x) { return (uint8_t)(x >> 16); }
static inline uint8_t u8c(uint32_t x) { return (uint8_t)(x >> 8); }
static inline uint8_t u8d(uint32_t x) { return (uint8_t)x; }

static inline uint32_t rotl32(uint32_t x, uint32_t n)
{
    n &= 31;
    return (x << n) | (x >> ((32 - n) & 31));
}

static inline uint32_t f1(uint32_t d, uint32_t km, uint32_t kr)
{
    uint32_t t = rotl32(km + d, kr);
    return ((cast_sbox1[u8a(t)] ^ cast_sbox2[u8b(t)]) - cast_sbox3[u8c(t)]) +
           cast_sbox4[u8d(t)];
}

static inline uint32_t f2(uint32_t d, uint32_t km, uint32_t kr)
{
    uint32_t t = rotl32(km ^ d, kr);
    return ((cast_sbox1[u8a(t)] - cast_sbox2[u8b(t)]) + cast_sbox3[u8c(t)]) ^
           cast_sbox4[u8d(t)];
}

static inline uint32_t f3(uint32_t d, uint32_t km, uint32_t kr)
{
    uint32_t t = rotl32(km - d, kr);
    return ((cast_sbox1[u8a(t)] + cast_sbox2[u8b(t)]) ^ cast_sbox3[u8c(t)]) -
           cast_sbox4[u8d(t)];
}

int cast5_set_key(cast5_ctx *ctx, const uint8_t *key, size_t key_len)
{
    uint32_t t[4];
    uint32_t z[4];
    uint32_t x[4];
    int i;

    if (!ctx || !key || key_len < CAST5_MIN_KEY_SIZE || key_len > CAST5_MAX_KEY_SIZE) {
        return -1;
    }

    ctx->rounds = (key_len <= 10) ? 12 : 16;

    for (i = 0; i < 4; i++) {
        x[i] = 0;
        if ((size_t)(i * 4 + 0) < key_len) x[i] = (uint32_t)key[i * 4 + 0] << 24;
        if ((size_t)(i * 4 + 1) < key_len) x[i] |= (uint32_t)key[i * 4 + 1] << 16;
        if ((size_t)(i * 4 + 2) < key_len) x[i] |= (uint32_t)key[i * 4 + 2] << 8;
        if ((size_t)(i * 4 + 3) < key_len) x[i] |= (uint32_t)key[i * 4 + 3];
    }

    for (i = 0; i < 32; i += 4) {
        switch (i & 4) {
        case 0:
            t[0] = z[0] = x[0] ^ cast_sbox5[u8b(x[3])] ^
                           cast_sbox6[u8d(x[3])] ^ cast_sbox7[u8a(x[3])] ^
                           cast_sbox8[u8c(x[3])] ^ cast_sbox7[u8a(x[2])];
            t[1] = z[1] = x[2] ^ cast_sbox5[u8a(z[0])] ^
                           cast_sbox6[u8c(z[0])] ^ cast_sbox7[u8b(z[0])] ^
                           cast_sbox8[u8d(z[0])] ^ cast_sbox8[u8c(x[2])];
            t[2] = z[2] = x[3] ^ cast_sbox5[u8d(z[1])] ^
                           cast_sbox6[u8c(z[1])] ^ cast_sbox7[u8b(z[1])] ^
                           cast_sbox8[u8a(z[1])] ^ cast_sbox5[u8b(x[2])];
            t[3] = z[3] = x[1] ^ cast_sbox5[u8c(z[2])] ^
                           cast_sbox6[u8b(z[2])] ^ cast_sbox7[u8d(z[2])] ^
                           cast_sbox8[u8a(z[2])] ^ cast_sbox6[u8d(x[2])];
            break;
        case 4:
            t[0] = x[0] = z[2] ^ cast_sbox5[u8b(z[1])] ^
                           cast_sbox6[u8d(z[1])] ^ cast_sbox7[u8a(z[1])] ^
                           cast_sbox8[u8c(z[1])] ^ cast_sbox7[u8a(z[0])];
            t[1] = x[1] = z[0] ^ cast_sbox5[u8a(x[0])] ^
                           cast_sbox6[u8c(x[0])] ^ cast_sbox7[u8b(x[0])] ^
                           cast_sbox8[u8d(x[0])] ^ cast_sbox8[u8c(z[0])];
            t[2] = x[2] = z[1] ^ cast_sbox5[u8d(x[1])] ^
                           cast_sbox6[u8c(x[1])] ^ cast_sbox7[u8b(x[1])] ^
                           cast_sbox8[u8a(x[1])] ^ cast_sbox5[u8b(z[0])];
            t[3] = x[3] = z[3] ^ cast_sbox5[u8c(x[2])] ^
                           cast_sbox6[u8b(x[2])] ^ cast_sbox7[u8d(x[2])] ^
                           cast_sbox8[u8a(x[2])] ^ cast_sbox6[u8d(z[0])];
            break;
        }
        switch (i & 12) {
        case 0:
        case 12:
            ctx->subkeys[i + 0] = cast_sbox5[u8a(t[2])] ^ cast_sbox6[u8b(t[2])] ^
                                 cast_sbox7[u8d(t[1])] ^ cast_sbox8[u8c(t[1])];
            ctx->subkeys[i + 1] = cast_sbox5[u8c(t[2])] ^ cast_sbox6[u8d(t[2])] ^
                                 cast_sbox7[u8b(t[1])] ^ cast_sbox8[u8a(t[1])];
            ctx->subkeys[i + 2] = cast_sbox5[u8a(t[3])] ^ cast_sbox6[u8b(t[3])] ^
                                 cast_sbox7[u8d(t[0])] ^ cast_sbox8[u8c(t[0])];
            ctx->subkeys[i + 3] = cast_sbox5[u8c(t[3])] ^ cast_sbox6[u8d(t[3])] ^
                                 cast_sbox7[u8b(t[0])] ^ cast_sbox8[u8a(t[0])];
            break;
        case 4:
        case 8:
            ctx->subkeys[i + 0] = cast_sbox5[u8d(t[0])] ^ cast_sbox6[u8c(t[0])] ^
                                 cast_sbox7[u8a(t[3])] ^ cast_sbox8[u8b(t[3])];
            ctx->subkeys[i + 1] = cast_sbox5[u8b(t[0])] ^ cast_sbox6[u8a(t[0])] ^
                                 cast_sbox7[u8c(t[3])] ^ cast_sbox8[u8d(t[3])];
            ctx->subkeys[i + 2] = cast_sbox5[u8d(t[1])] ^ cast_sbox6[u8c(t[1])] ^
                                 cast_sbox7[u8a(t[2])] ^ cast_sbox8[u8b(t[2])];
            ctx->subkeys[i + 3] = cast_sbox5[u8b(t[1])] ^ cast_sbox6[u8a(t[1])] ^
                                 cast_sbox7[u8c(t[2])] ^ cast_sbox8[u8d(t[2])];
            break;
        }
        switch (i & 12) {
        case 0:
            ctx->subkeys[i + 0] ^= cast_sbox5[u8c(z[0])];
            ctx->subkeys[i + 1] ^= cast_sbox6[u8c(z[1])];
            ctx->subkeys[i + 2] ^= cast_sbox7[u8b(z[2])];
            ctx->subkeys[i + 3] ^= cast_sbox8[u8a(z[3])];
            break;
        case 4:
            ctx->subkeys[i + 0] ^= cast_sbox5[u8a(x[2])];
            ctx->subkeys[i + 1] ^= cast_sbox6[u8b(x[3])];
            ctx->subkeys[i + 2] ^= cast_sbox7[u8d(x[0])];
            ctx->subkeys[i + 3] ^= cast_sbox8[u8d(x[1])];
            break;
        case 8:
            ctx->subkeys[i + 0] ^= cast_sbox5[u8b(z[2])];
            ctx->subkeys[i + 1] ^= cast_sbox6[u8a(z[3])];
            ctx->subkeys[i + 2] ^= cast_sbox7[u8c(z[0])];
            ctx->subkeys[i + 3] ^= cast_sbox8[u8c(z[1])];
            break;
        case 12:
            ctx->subkeys[i + 0] ^= cast_sbox5[u8d(x[0])];
            ctx->subkeys[i + 1] ^= cast_sbox6[u8d(x[1])];
            ctx->subkeys[i + 2] ^= cast_sbox7[u8a(x[2])];
            ctx->subkeys[i + 3] ^= cast_sbox8[u8b(x[3])];
            break;
        }
        if (i >= 16) {
            ctx->subkeys[i + 0] &= 31;
            ctx->subkeys[i + 1] &= 31;
            ctx->subkeys[i + 2] &= 31;
            ctx->subkeys[i + 3] &= 31;
        }
    }

    memset(t, 0, sizeof(t));
    memset(x, 0, sizeof(x));
    memset(z, 0, sizeof(z));

    return 0;
}

void cast5_encrypt_block(const cast5_ctx *ctx, const uint8_t *in, uint8_t *out)
{
    uint32_t l = load_be32(in);
    uint32_t r = load_be32(in + 4);

    l ^= f1(r, ctx->subkeys[0], ctx->subkeys[16]);
    r ^= f2(l, ctx->subkeys[1], ctx->subkeys[17]);
    l ^= f3(r, ctx->subkeys[2], ctx->subkeys[18]);
    r ^= f1(l, ctx->subkeys[3], ctx->subkeys[19]);
    l ^= f2(r, ctx->subkeys[4], ctx->subkeys[20]);
    r ^= f3(l, ctx->subkeys[5], ctx->subkeys[21]);
    l ^= f1(r, ctx->subkeys[6], ctx->subkeys[22]);
    r ^= f2(l, ctx->subkeys[7], ctx->subkeys[23]);
    l ^= f3(r, ctx->subkeys[8], ctx->subkeys[24]);
    r ^= f1(l, ctx->subkeys[9], ctx->subkeys[25]);
    l ^= f2(r, ctx->subkeys[10], ctx->subkeys[26]);
    r ^= f3(l, ctx->subkeys[11], ctx->subkeys[27]);

    if (ctx->rounds > 12) {
        l ^= f1(r, ctx->subkeys[12], ctx->subkeys[28]);
        r ^= f2(l, ctx->subkeys[13], ctx->subkeys[29]);
        l ^= f3(r, ctx->subkeys[14], ctx->subkeys[30]);
        r ^= f1(l, ctx->subkeys[15], ctx->subkeys[31]);
    }

    store_be32(out, r);
    store_be32(out + 4, l);
}

void cast5_decrypt_block(const cast5_ctx *ctx, const uint8_t *in, uint8_t *out)
{
    uint32_t r = load_be32(in);
    uint32_t l = load_be32(in + 4);

    if (ctx->rounds > 12) {
        r ^= f1(l, ctx->subkeys[15], ctx->subkeys[31]);
        l ^= f3(r, ctx->subkeys[14], ctx->subkeys[30]);
        r ^= f2(l, ctx->subkeys[13], ctx->subkeys[29]);
        l ^= f1(r, ctx->subkeys[12], ctx->subkeys[28]);
    }

    r ^= f3(l, ctx->subkeys[11], ctx->subkeys[27]);
    l ^= f2(r, ctx->subkeys[10], ctx->subkeys[26]);
    r ^= f1(l, ctx->subkeys[9], ctx->subkeys[25]);
    l ^= f3(r, ctx->subkeys[8], ctx->subkeys[24]);
    r ^= f2(l, ctx->subkeys[7], ctx->subkeys[23]);
    l ^= f1(r, ctx->subkeys[6], ctx->subkeys[22]);
    r ^= f3(l, ctx->subkeys[5], ctx->subkeys[21]);
    l ^= f2(r, ctx->subkeys[4], ctx->subkeys[20]);
    r ^= f1(l, ctx->subkeys[3], ctx->subkeys[19]);
    l ^= f3(r, ctx->subkeys[2], ctx->subkeys[18]);
    r ^= f2(l, ctx->subkeys[1], ctx->subkeys[17]);
    l ^= f1(r, ctx->subkeys[0], ctx->subkeys[16]);

    store_be32(out, l);
    store_be32(out + 4, r);
}

void cast5_cbc_encrypt(const cast5_ctx *ctx,
                       const uint8_t *iv,
                       const uint8_t *in,
                       uint8_t *out,
                       size_t len)
{
    uint8_t prev[CAST5_BLOCK_SIZE];
    uint8_t block[CAST5_BLOCK_SIZE];
    size_t i;
    int j;

    memcpy(prev, iv, CAST5_BLOCK_SIZE);

    for (i = 0; i < len; i += CAST5_BLOCK_SIZE) {
        for (j = 0; j < CAST5_BLOCK_SIZE; j++) {
            block[j] = in[i + (size_t)j] ^ prev[j];
        }
        cast5_encrypt_block(ctx, block, &out[i]);
        memcpy(prev, &out[i], CAST5_BLOCK_SIZE);
    }
}

void cast5_cbc_decrypt(const cast5_ctx *ctx,
                       const uint8_t *iv,
                       const uint8_t *in,
                       uint8_t *out,
                       size_t len)
{
    uint8_t prev[CAST5_BLOCK_SIZE];
    uint8_t temp[CAST5_BLOCK_SIZE];
    uint8_t block[CAST5_BLOCK_SIZE];
    size_t i;
    int j;

    memcpy(prev, iv, CAST5_BLOCK_SIZE);

    for (i = 0; i < len; i += CAST5_BLOCK_SIZE) {
        memcpy(temp, &in[i], CAST5_BLOCK_SIZE);
        cast5_decrypt_block(ctx, &in[i], block);
        for (j = 0; j < CAST5_BLOCK_SIZE; j++) {
            out[i + (size_t)j] = block[j] ^ prev[j];
        }
        memcpy(prev, temp, CAST5_BLOCK_SIZE);
    }
}
