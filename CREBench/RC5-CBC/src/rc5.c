/*
 * RC5 Block Cipher Implementation
 * 
 * Based on the original RC5 algorithm by Ronald Rivest and the
 * Crypto++ implementation by Wei Dai.
 * 
 * For educational and CTF purposes only.
 */

#include "rc5.h"
#include <string.h>

#ifdef CONSTXOR_RC5_TABLES
#include "constxor_tables.h"
#define RC5_MAGIC_TABLE (constxor_rc5_magic())
#else
static const uint32_t rc5_magic[2] = {
    0xB7E15163UL,
    0x9E3779B9UL
};
#define RC5_MAGIC_TABLE (rc5_magic)
#endif

#define RC5_P32 (RC5_MAGIC_TABLE[0])
#define RC5_Q32 (RC5_MAGIC_TABLE[1])

/* Rotate left */
#define ROTL32(x, n) (((x) << ((n) & 31)) | ((x) >> (32 - ((n) & 31))))

/* Rotate right */
#define ROTR32(x, n) (((x) >> ((n) & 31)) | ((x) << (32 - ((n) & 31))))

/* Load 32-bit word from bytes (little-endian) */
static inline uint32_t load_le32(const uint8_t *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/* Store 32-bit word to bytes (little-endian) */
static inline void store_le32(uint8_t *p, uint32_t x)
{
    p[0] = (uint8_t)(x);
    p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
}

int rc5_set_key(rc5_ctx *ctx, const uint8_t *key, size_t key_len, unsigned int rounds)
{
    unsigned int i, j, k, n;
    uint32_t A, B;
    uint32_t L[64];  /* Key buffer (max 256 bytes / 4 = 64 words) */
    unsigned int c;  /* Number of 32-bit words in key */
    unsigned int t;  /* Size of S table */

    if (rounds > RC5_MAX_ROUNDS || key_len > RC5_MAX_KEY_SIZE) {
        return -1;
    }

    ctx->rounds = rounds;
    t = 2 * (rounds + 1);

    /* Calculate c = number of 32-bit words in key (min 1) */
    c = (unsigned int)((key_len + 3) / 4);
    if (c == 0) c = 1;

    /* Copy key into L array in little-endian format */
    memset(L, 0, sizeof(L));
    for (i = 0; i < key_len; i++) {
        L[i / 4] |= (uint32_t)key[i] << (8 * (i % 4));
    }

    /* Initialize S table with magic constants */
    ctx->S[0] = RC5_P32;
    for (i = 1; i < t; i++) {
        ctx->S[i] = ctx->S[i - 1] + RC5_Q32;
    }

    /* Mix in the key */
    A = B = 0;
    n = 3 * (t > c ? t : c);

    for (i = 0, j = 0, k = 0; k < n; k++) {
        A = ctx->S[i] = ROTL32(ctx->S[i] + A + B, 3);
        B = L[j] = ROTL32(L[j] + A + B, (A + B) & 31);
        i = (i + 1) % t;
        j = (j + 1) % c;
    }

    return 0;
}

void rc5_encrypt_block(const rc5_ctx *ctx, const uint8_t *in, uint8_t *out)
{
    uint32_t A, B;
    unsigned int i;
    const uint32_t *S = ctx->S;

    /* Load block (little-endian) */
    A = load_le32(in);
    B = load_le32(in + 4);

    /* Add first round key */
    A += S[0];
    B += S[1];

    /* Encryption rounds */
    for (i = 1; i <= ctx->rounds; i++) {
        A = ROTL32(A ^ B, B & 31) + S[2 * i];
        B = ROTL32(B ^ A, A & 31) + S[2 * i + 1];
    }

    /* Store result (little-endian) */
    store_le32(out, A);
    store_le32(out + 4, B);
}

void rc5_decrypt_block(const rc5_ctx *ctx, const uint8_t *in, uint8_t *out)
{
    uint32_t A, B;
    unsigned int i;
    const uint32_t *S = ctx->S;

    /* Load block (little-endian) */
    A = load_le32(in);
    B = load_le32(in + 4);

    /* Decryption rounds (reverse order) */
    for (i = ctx->rounds; i >= 1; i--) {
        B = ROTR32(B - S[2 * i + 1], A & 31) ^ A;
        A = ROTR32(A - S[2 * i], B & 31) ^ B;
    }

    /* Subtract first round key */
    B -= S[1];
    A -= S[0];

    /* Store result (little-endian) */
    store_le32(out, A);
    store_le32(out + 4, B);
}

void rc5_cbc_encrypt(const rc5_ctx *ctx,
                     const uint8_t *iv,
                     const uint8_t *in,
                     uint8_t *out,
                     size_t len)
{
    uint8_t prev[RC5_BLOCK_SIZE];
    uint8_t block[RC5_BLOCK_SIZE];
    size_t i;
    int j;

    memcpy(prev, iv, RC5_BLOCK_SIZE);

    for (i = 0; i < len; i += RC5_BLOCK_SIZE) {
        for (j = 0; j < RC5_BLOCK_SIZE; j++) {
            block[j] = in[i + j] ^ prev[j];
        }
        rc5_encrypt_block(ctx, block, &out[i]);
        memcpy(prev, &out[i], RC5_BLOCK_SIZE);
    }
}

void rc5_cbc_decrypt(const rc5_ctx *ctx,
                     const uint8_t *iv,
                     const uint8_t *in,
                     uint8_t *out,
                     size_t len)
{
    uint8_t prev[RC5_BLOCK_SIZE];
    uint8_t temp[RC5_BLOCK_SIZE];
    uint8_t decrypted[RC5_BLOCK_SIZE];
    size_t i;
    int j;

    memcpy(prev, iv, RC5_BLOCK_SIZE);

    for (i = 0; i < len; i += RC5_BLOCK_SIZE) {
        memcpy(temp, &in[i], RC5_BLOCK_SIZE);
        rc5_decrypt_block(ctx, &in[i], decrypted);
        for (j = 0; j < RC5_BLOCK_SIZE; j++) {
            out[i + j] = decrypted[j] ^ prev[j];
        }
        memcpy(prev, temp, RC5_BLOCK_SIZE);
    }
}
