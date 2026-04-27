/*
 * 3-Way Block Cipher Implementation
 *
 * Public-domain design by Joan Daemen. This implementation follows the
 * Crypto++ reference (3way.cpp) and uses fixed 96-bit keys and blocks.
 *
 * For educational and CTF purposes only.
 */

#include "threeway.h"
#include <string.h>

#ifdef CONSTXOR_THREEWAY_TABLES
#include "constxor_tables.h"
#define THREEWAY_MAGIC_TABLE (constxor_threeway_magic())
#else
static const uint32_t threeway_magic[3] = {0x0B0BU, 0xB1B1U, 0x11011U};
#define THREEWAY_MAGIC_TABLE (threeway_magic)
#endif

#define THREEWAY_START_E_VALUE (THREEWAY_MAGIC_TABLE[0])
#define THREEWAY_START_D_VALUE (THREEWAY_MAGIC_TABLE[1])
#define THREEWAY_RC_POLY_VALUE (THREEWAY_MAGIC_TABLE[2])

static uint32_t rotl32(uint32_t v, unsigned int n)
{
    return (v << n) | (v >> (32U - n));
}

static uint32_t reverse_bits(uint32_t a)
{
    a = ((a & 0xAAAAAAAAu) >> 1) | ((a & 0x55555555u) << 1);
    a = ((a & 0xCCCCCCCCu) >> 2) | ((a & 0x33333333u) << 2);
    return ((a & 0xF0F0F0F0u) >> 4) | ((a & 0x0F0F0F0Fu) << 4);
}

static uint32_t byte_reverse32(uint32_t v)
{
    return (v >> 24) | ((v >> 8) & 0x0000FF00u) | ((v << 8) & 0x00FF0000u) | (v << 24);
}

static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

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

static void mu(uint32_t *a0, uint32_t *a1, uint32_t *a2)
{
    uint32_t t = reverse_bits(*a0);
    *a1 = reverse_bits(*a1);
    *a0 = reverse_bits(*a2);
    *a2 = t;
}

static void pi_gamma_pi(uint32_t *a0, uint32_t *a1, uint32_t *a2)
{
    uint32_t b2 = rotl32(*a2, 1);
    uint32_t b0 = rotl32(*a0, 22);
    *a0 = rotl32(b0 ^ (*a1 | (~b2)), 1);
    *a2 = rotl32(b2 ^ (b0 | (~*a1)), 22);
    *a1 ^= (b2 | (~b0));
}

static void theta(uint32_t *a0, uint32_t *a1, uint32_t *a2)
{
    uint32_t b0, b1, c;
    c = *a0 ^ *a1 ^ *a2;
    c = rotl32(c, 16) ^ rotl32(c, 8);
    b0 = (*a0 << 24) ^ (*a2 >> 8) ^ (*a1 << 8) ^ (*a0 >> 24);
    b1 = (*a1 << 24) ^ (*a0 >> 8) ^ (*a2 << 8) ^ (*a1 >> 24);
    *a0 ^= c ^ b0;
    *a1 ^= c ^ b1;
    *a2 ^= c ^ (b0 >> 16) ^ (b1 << 16);
}

static void rho(uint32_t *a0, uint32_t *a1, uint32_t *a2)
{
    theta(a0, a1, a2);
    pi_gamma_pi(a0, a1, a2);
}

static uint32_t next_rc(uint32_t rc)
{
    rc <<= 1;
    if (rc & 0x10000u) {
        rc ^= THREEWAY_RC_POLY_VALUE;
    }
    return rc;
}

static __attribute__((noinline)) void threeway_store_encrypt_key_words(threeway_ctx *ctx,
                                                                       const uint8_t *key,
                                                                       unsigned int rounds)
{
    ctx->rounds = rounds;
    ctx->k[0] = load_be32(key);
    ctx->k[1] = load_be32(key + 4);
    ctx->k[2] = load_be32(key + 8);
}

int threeway_set_encrypt_key(threeway_ctx *ctx, const uint8_t *key, unsigned int rounds)
{
    unsigned int effective_rounds;

    if (ctx == NULL || key == NULL) {
        return -1;
    }

    effective_rounds = rounds != 0 ? rounds : THREEWAY_ROUNDS;
    threeway_store_encrypt_key_words(ctx, key, effective_rounds);

    return 0;
}

int threeway_set_decrypt_key(threeway_ctx *ctx, const uint8_t *key, unsigned int rounds)
{
    uint32_t k0, k1, k2;

    if (ctx == NULL || key == NULL) {
        return -1;
    }

    if (rounds == 0) {
        rounds = THREEWAY_ROUNDS;
    }

    k0 = load_be32(key);
    k1 = load_be32(key + 4);
    k2 = load_be32(key + 8);

    theta(&k0, &k1, &k2);
    mu(&k0, &k1, &k2);
    k0 = byte_reverse32(k0);
    k1 = byte_reverse32(k1);
    k2 = byte_reverse32(k2);

    ctx->rounds = rounds;
    ctx->k[0] = k0;
    ctx->k[1] = k1;
    ctx->k[2] = k2;

    return 0;
}

void threeway_encrypt_block(const threeway_ctx *ctx, const uint8_t *in, uint8_t *out)
{
    uint32_t a0, a1, a2;
    uint32_t rc;

    a0 = load_be32(in);
    a1 = load_be32(in + 4);
    a2 = load_be32(in + 8);

    rc = THREEWAY_START_E_VALUE;
    for (unsigned int i = 0; i < ctx->rounds; i++) {
        a0 ^= ctx->k[0] ^ (rc << 16);
        a1 ^= ctx->k[1];
        a2 ^= ctx->k[2] ^ rc;
        rho(&a0, &a1, &a2);
        rc = next_rc(rc);
    }

    a0 ^= ctx->k[0] ^ (rc << 16);
    a1 ^= ctx->k[1];
    a2 ^= ctx->k[2] ^ rc;
    theta(&a0, &a1, &a2);

    store_be32(out, a0);
    store_be32(out + 4, a1);
    store_be32(out + 8, a2);
}

void threeway_decrypt_block(const threeway_ctx *ctx, const uint8_t *in, uint8_t *out)
{
    uint32_t a0, a1, a2;
    uint32_t rc;

    a0 = load_le32(in);
    a1 = load_le32(in + 4);
    a2 = load_le32(in + 8);

    mu(&a0, &a1, &a2);
    rc = THREEWAY_START_D_VALUE;
    for (unsigned int i = 0; i < ctx->rounds; i++) {
        a0 ^= ctx->k[0] ^ (rc << 16);
        a1 ^= ctx->k[1];
        a2 ^= ctx->k[2] ^ rc;
        rho(&a0, &a1, &a2);
        rc = next_rc(rc);
    }

    a0 ^= ctx->k[0] ^ (rc << 16);
    a1 ^= ctx->k[1];
    a2 ^= ctx->k[2] ^ rc;
    theta(&a0, &a1, &a2);
    mu(&a0, &a1, &a2);

    store_le32(out, a0);
    store_le32(out + 4, a1);
    store_le32(out + 8, a2);
}

void threeway_ecb_encrypt(const threeway_ctx *ctx, const uint8_t *in, uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i += THREEWAY_BLOCK_SIZE) {
        threeway_encrypt_block(ctx, &in[i], &out[i]);
    }
}

void threeway_ecb_decrypt(const threeway_ctx *ctx, const uint8_t *in, uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i += THREEWAY_BLOCK_SIZE) {
        threeway_decrypt_block(ctx, &in[i], &out[i]);
    }
}

void threeway_cbc_encrypt(const threeway_ctx *ctx, const uint8_t *iv,
                          const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t prev[THREEWAY_BLOCK_SIZE];

    memcpy(prev, iv, THREEWAY_BLOCK_SIZE);
    for (size_t i = 0; i < len; i += THREEWAY_BLOCK_SIZE) {
        uint8_t block[THREEWAY_BLOCK_SIZE];
        for (size_t j = 0; j < THREEWAY_BLOCK_SIZE; j++) {
            block[j] = in[i + j] ^ prev[j];
        }
        threeway_encrypt_block(ctx, block, &out[i]);
        memcpy(prev, &out[i], THREEWAY_BLOCK_SIZE);
    }
}

void threeway_cbc_decrypt(const threeway_ctx *ctx, const uint8_t *iv,
                          const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t prev[THREEWAY_BLOCK_SIZE];
    uint8_t curr[THREEWAY_BLOCK_SIZE];

    memcpy(prev, iv, THREEWAY_BLOCK_SIZE);
    for (size_t i = 0; i < len; i += THREEWAY_BLOCK_SIZE) {
        memcpy(curr, &in[i], THREEWAY_BLOCK_SIZE);
        threeway_decrypt_block(ctx, &in[i], &out[i]);
        for (size_t j = 0; j < THREEWAY_BLOCK_SIZE; j++) {
            out[i + j] ^= prev[j];
        }
        memcpy(prev, curr, THREEWAY_BLOCK_SIZE);
    }
}
