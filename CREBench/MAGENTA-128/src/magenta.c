/*
 * MAGENTA-128 Block Cipher (CBC mode)
 *
 * Based on the reference MAGENTA implementation by Dr. Brian Gladman
 * and the MAGENTA specification. This implementation supports 128-bit
 * keys and provides CBC mode encryption/decryption.
 */

#include "magenta.h"
#include <string.h>

#ifdef CONSTXOR_MAGENTA_TABLES
#include "constxor_tables.h"
#define MAGENTA_GF_POLY_VALUE (constxor_magenta_gf_poly()[0])
#else
static const uint32_t magenta_gf_poly[1] = {0x0165u};
#define MAGENTA_GF_POLY_VALUE (magenta_gf_poly[0])
#endif

static uint8_t f_tab[256];
static int tab_init = 0;

static uint32_t load_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint8_t byte_of(uint32_t x, unsigned int n)
{
    return (uint8_t)(x >> (8U * n));
}

static void init_tab(void)
{
    uint32_t f = 1;
    for (uint32_t i = 0; i < 255; ++i) {
        f_tab[i] = (uint8_t)f;
        f <<= 1;
        if (f & 0x100u) {
            f ^= MAGENTA_GF_POLY_VALUE;
        }
    }
    f_tab[255] = 0;
}

static void pi_fun(uint32_t y[4], const uint32_t x[4])
{
    y[0] = (uint32_t)f_tab[byte_of(x[0], 0) ^ f_tab[byte_of(x[2], 0)]]
         | ((uint32_t)f_tab[byte_of(x[2], 0) ^ f_tab[byte_of(x[0], 0)]] << 8)
         | ((uint32_t)f_tab[byte_of(x[0], 1) ^ f_tab[byte_of(x[2], 1)]] << 16)
         | ((uint32_t)f_tab[byte_of(x[2], 1) ^ f_tab[byte_of(x[0], 1)]] << 24);

    y[1] = (uint32_t)f_tab[byte_of(x[0], 2) ^ f_tab[byte_of(x[2], 2)]]
         | ((uint32_t)f_tab[byte_of(x[2], 2) ^ f_tab[byte_of(x[0], 2)]] << 8)
         | ((uint32_t)f_tab[byte_of(x[0], 3) ^ f_tab[byte_of(x[2], 3)]] << 16)
         | ((uint32_t)f_tab[byte_of(x[2], 3) ^ f_tab[byte_of(x[0], 3)]] << 24);

    y[2] = (uint32_t)f_tab[byte_of(x[1], 0) ^ f_tab[byte_of(x[3], 0)]]
         | ((uint32_t)f_tab[byte_of(x[3], 0) ^ f_tab[byte_of(x[1], 0)]] << 8)
         | ((uint32_t)f_tab[byte_of(x[1], 1) ^ f_tab[byte_of(x[3], 1)]] << 16)
         | ((uint32_t)f_tab[byte_of(x[3], 1) ^ f_tab[byte_of(x[1], 1)]] << 24);

    y[3] = (uint32_t)f_tab[byte_of(x[1], 2) ^ f_tab[byte_of(x[3], 2)]]
         | ((uint32_t)f_tab[byte_of(x[3], 2) ^ f_tab[byte_of(x[1], 2)]] << 8)
         | ((uint32_t)f_tab[byte_of(x[1], 3) ^ f_tab[byte_of(x[3], 3)]] << 16)
         | ((uint32_t)f_tab[byte_of(x[3], 3) ^ f_tab[byte_of(x[1], 3)]] << 24);
}

static void e3_fun(uint32_t x[4])
{
    uint32_t u[4];
    uint32_t v[4];

    u[0] = x[0];
    u[1] = x[1];
    u[2] = x[2];
    u[3] = x[3];

    pi_fun(v, u); pi_fun(u, v); pi_fun(v, u); pi_fun(u, v);

    v[0] = (uint32_t)byte_of(u[0], 0) | ((uint32_t)byte_of(u[0], 2) << 8)
         | ((uint32_t)byte_of(u[1], 0) << 16) | ((uint32_t)byte_of(u[1], 2) << 24);
    v[1] = (uint32_t)byte_of(u[2], 0) | ((uint32_t)byte_of(u[2], 2) << 8)
         | ((uint32_t)byte_of(u[3], 0) << 16) | ((uint32_t)byte_of(u[3], 2) << 24);
    v[2] = (uint32_t)byte_of(u[0], 1) | ((uint32_t)byte_of(u[0], 3) << 8)
         | ((uint32_t)byte_of(u[1], 1) << 16) | ((uint32_t)byte_of(u[1], 3) << 24);
    v[3] = (uint32_t)byte_of(u[2], 1) | ((uint32_t)byte_of(u[2], 3) << 8)
         | ((uint32_t)byte_of(u[3], 1) << 16) | ((uint32_t)byte_of(u[3], 3) << 24);

    u[0] = x[0] ^ v[0];
    u[1] = x[1] ^ v[1];
    u[2] = x[2] ^ v[2];
    u[3] = x[3] ^ v[3];

    pi_fun(v, u); pi_fun(u, v); pi_fun(v, u); pi_fun(u, v);

    v[0] = (uint32_t)byte_of(u[0], 0) | ((uint32_t)byte_of(u[0], 2) << 8)
         | ((uint32_t)byte_of(u[1], 0) << 16) | ((uint32_t)byte_of(u[1], 2) << 24);
    v[1] = (uint32_t)byte_of(u[2], 0) | ((uint32_t)byte_of(u[2], 2) << 8)
         | ((uint32_t)byte_of(u[3], 0) << 16) | ((uint32_t)byte_of(u[3], 2) << 24);
    v[2] = (uint32_t)byte_of(u[0], 1) | ((uint32_t)byte_of(u[0], 3) << 8)
         | ((uint32_t)byte_of(u[1], 1) << 16) | ((uint32_t)byte_of(u[1], 3) << 24);
    v[3] = (uint32_t)byte_of(u[2], 1) | ((uint32_t)byte_of(u[2], 3) << 8)
         | ((uint32_t)byte_of(u[3], 1) << 16) | ((uint32_t)byte_of(u[3], 3) << 24);

    u[0] = x[0] ^ v[0];
    u[1] = x[1] ^ v[1];
    u[2] = x[2] ^ v[2];
    u[3] = x[3] ^ v[3];

    pi_fun(v, u); pi_fun(u, v); pi_fun(v, u); pi_fun(u, v);

    v[0] = (uint32_t)byte_of(u[0], 0) | ((uint32_t)byte_of(u[0], 2) << 8)
         | ((uint32_t)byte_of(u[1], 0) << 16) | ((uint32_t)byte_of(u[1], 2) << 24);
    v[1] = (uint32_t)byte_of(u[2], 0) | ((uint32_t)byte_of(u[2], 2) << 8)
         | ((uint32_t)byte_of(u[3], 0) << 16) | ((uint32_t)byte_of(u[3], 2) << 24);

    x[0] = v[0];
    x[1] = v[1];
}

static void r_fun(uint32_t x[2], const uint32_t y[2], const uint32_t k[2])
{
    uint32_t tt[4];

    tt[0] = y[0];
    tt[1] = y[1];
    tt[2] = k[0];
    tt[3] = k[1];

    e3_fun(tt);

    x[0] ^= tt[0];
    x[1] ^= tt[1];
}

static void magenta_encrypt_words(const magenta_ctx *ctx, const uint32_t in_blk[4], uint32_t out_blk[4])
{
    uint32_t blk[4];

    blk[0] = in_blk[0];
    blk[1] = in_blk[1];
    blk[2] = in_blk[2];
    blk[3] = in_blk[3];

    r_fun(blk, blk + 2, ctx->l_key);
    r_fun(blk + 2, blk, ctx->l_key + 2);

    r_fun(blk, blk + 2, ctx->l_key + 4);
    r_fun(blk + 2, blk, ctx->l_key + 6);

    r_fun(blk, blk + 2, ctx->l_key + 8);
    r_fun(blk + 2, blk, ctx->l_key + 10);

    out_blk[0] = blk[0];
    out_blk[1] = blk[1];
    out_blk[2] = blk[2];
    out_blk[3] = blk[3];
}

static void magenta_decrypt_words(const magenta_ctx *ctx, const uint32_t in_blk[4], uint32_t out_blk[4])
{
    uint32_t blk[4];

    blk[2] = in_blk[0];
    blk[3] = in_blk[1];
    blk[0] = in_blk[2];
    blk[1] = in_blk[3];

    r_fun(blk, blk + 2, ctx->l_key);
    r_fun(blk + 2, blk, ctx->l_key + 2);

    r_fun(blk, blk + 2, ctx->l_key + 4);
    r_fun(blk + 2, blk, ctx->l_key + 6);

    r_fun(blk, blk + 2, ctx->l_key + 8);
    r_fun(blk + 2, blk, ctx->l_key + 10);

    out_blk[2] = blk[0];
    out_blk[3] = blk[1];
    out_blk[0] = blk[2];
    out_blk[1] = blk[3];
}

static void magenta_encrypt_block(const magenta_ctx *ctx, const uint8_t *in, uint8_t *out)
{
    uint32_t in_blk[4];
    uint32_t out_blk[4];

    in_blk[0] = load_le32(in);
    in_blk[1] = load_le32(in + 4);
    in_blk[2] = load_le32(in + 8);
    in_blk[3] = load_le32(in + 12);

    magenta_encrypt_words(ctx, in_blk, out_blk);

    store_le32(out, out_blk[0]);
    store_le32(out + 4, out_blk[1]);
    store_le32(out + 8, out_blk[2]);
    store_le32(out + 12, out_blk[3]);
}

static void magenta_decrypt_block(const magenta_ctx *ctx, const uint8_t *in, uint8_t *out)
{
    uint32_t in_blk[4];
    uint32_t out_blk[4];

    in_blk[0] = load_le32(in);
    in_blk[1] = load_le32(in + 4);
    in_blk[2] = load_le32(in + 8);
    in_blk[3] = load_le32(in + 12);

    magenta_decrypt_words(ctx, in_blk, out_blk);

    store_le32(out, out_blk[0]);
    store_le32(out + 4, out_blk[1]);
    store_le32(out + 8, out_blk[2]);
    store_le32(out + 12, out_blk[3]);
}

static __attribute__((noinline)) void magenta_set_key_impl(magenta_ctx *ctx, const uint8_t *key)
{
    uint32_t k0, k1, k2, k3;

    if (!tab_init) {
        init_tab();
        tab_init = 1;
    }

    k0 = load_le32(key);
    k1 = load_le32(key + 4);
    k2 = load_le32(key + 8);
    k3 = load_le32(key + 12);

    ctx->l_key[0] = k0; ctx->l_key[1] = k1;
    ctx->l_key[2] = k0; ctx->l_key[3] = k1;
    ctx->l_key[4] = k2; ctx->l_key[5] = k3;
    ctx->l_key[6] = k2; ctx->l_key[7] = k3;
    ctx->l_key[8] = k0; ctx->l_key[9] = k1;
    ctx->l_key[10] = k0; ctx->l_key[11] = k1;
}

int magenta_set_key(magenta_ctx *ctx, const uint8_t *key, size_t key_len)
{
    if (ctx == NULL || key == NULL || key_len != MAGENTA_KEY_SIZE) {
        return -1;
    }

    magenta_set_key_impl(ctx, key);
    return 0;
}

void magenta_cbc_encrypt(const magenta_ctx *ctx, const uint8_t *iv,
                         const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t prev[MAGENTA_BLOCK_SIZE];

    memcpy(prev, iv, MAGENTA_BLOCK_SIZE);

    for (size_t i = 0; i < len; i += MAGENTA_BLOCK_SIZE) {
        uint8_t block[MAGENTA_BLOCK_SIZE];
        for (size_t j = 0; j < MAGENTA_BLOCK_SIZE; j++) {
            block[j] = in[i + j] ^ prev[j];
        }
        magenta_encrypt_block(ctx, block, &out[i]);
        memcpy(prev, &out[i], MAGENTA_BLOCK_SIZE);
    }
}

void magenta_cbc_decrypt(const magenta_ctx *ctx, const uint8_t *iv,
                         const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t prev[MAGENTA_BLOCK_SIZE];
    uint8_t curr[MAGENTA_BLOCK_SIZE];

    memcpy(prev, iv, MAGENTA_BLOCK_SIZE);

    for (size_t i = 0; i < len; i += MAGENTA_BLOCK_SIZE) {
        memcpy(curr, &in[i], MAGENTA_BLOCK_SIZE);
        magenta_decrypt_block(ctx, &in[i], &out[i]);
        for (size_t j = 0; j < MAGENTA_BLOCK_SIZE; j++) {
            out[i + j] ^= prev[j];
        }
        memcpy(prev, curr, MAGENTA_BLOCK_SIZE);
    }
}
