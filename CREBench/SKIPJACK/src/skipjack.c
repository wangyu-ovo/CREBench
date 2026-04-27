/*
 * Adapted for CREBench from public SKIPJACK implementations.
 *
 * Reference attributions:
 *   - Crypto++ skipjack.cpp:
 *       modified by Wei Dai from Paulo Barreto's skipjack32.c
 *       (public domain according to Paulo Barreto's website)
 *       includes implementation lineage:
 *         Panu Rissanen (1998.06.24),
 *         Mark Tillotson (1998.06.25),
 *         Paulo Barreto (1998.06.30)
 *   - LibTomCrypt skipjack.c:
 *       Skipjack implementation by Tom St Denis
 *       SPDX-License-Identifier: Unlicense
 */

#include "skipjack.h"

#include <string.h>

#ifdef CONSTXOR_SKIPJACK_TABLES
#include "constxor_tables.h"
#define SKIPJACK_SBOX_TABLE (constxor_skipjack_sbox())
#else
static const uint8_t sbox[256] = {
    0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3,0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9,
    0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28,
    0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53,
    0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2,
    0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8,
    0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90,
    0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76,
    0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d,
    0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18,
    0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4,
    0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40,
    0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5,
    0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2,
    0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8,
    0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac,
    0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46
};
#define SKIPJACK_SBOX_TABLE (sbox)
#endif

static const uint8_t keystep[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
static const uint8_t ikeystep[10] = { 9, 0, 1, 2, 3, 4, 5, 6, 7, 8 };

static uint16_t load_le16(const uint8_t *in)
{
    return (uint16_t)in[0] | (uint16_t)(in[1] << 8);
}

static void store_le16(uint8_t *out, uint16_t v)
{
    out[0] = (uint8_t)(v & 0xFF);
    out[1] = (uint8_t)((v >> 8) & 0xFF);
}

static uint16_t g_func(uint16_t w, int *kp, const uint8_t *key)
{
    uint8_t g1 = (uint8_t)(w >> 8);
    uint8_t g2 = (uint8_t)(w & 0xFF);

    g1 ^= SKIPJACK_SBOX_TABLE[g2 ^ key[*kp]];
    *kp = keystep[*kp];
    g2 ^= SKIPJACK_SBOX_TABLE[g1 ^ key[*kp]];
    *kp = keystep[*kp];
    g1 ^= SKIPJACK_SBOX_TABLE[g2 ^ key[*kp]];
    *kp = keystep[*kp];
    g2 ^= SKIPJACK_SBOX_TABLE[g1 ^ key[*kp]];
    *kp = keystep[*kp];

    return (uint16_t)(((uint16_t)g1 << 8) | g2);
}

static uint16_t ig_func(uint16_t w, int *kp, const uint8_t *key)
{
    uint8_t g1 = (uint8_t)(w >> 8);
    uint8_t g2 = (uint8_t)(w & 0xFF);

    *kp = ikeystep[*kp];
    g2 ^= SKIPJACK_SBOX_TABLE[g1 ^ key[*kp]];
    *kp = ikeystep[*kp];
    g1 ^= SKIPJACK_SBOX_TABLE[g2 ^ key[*kp]];
    *kp = ikeystep[*kp];
    g2 ^= SKIPJACK_SBOX_TABLE[g1 ^ key[*kp]];
    *kp = ikeystep[*kp];
    g1 ^= SKIPJACK_SBOX_TABLE[g2 ^ key[*kp]];

    return (uint16_t)(((uint16_t)g1 << 8) | g2);
}

int skipjack_set_key(skipjack_ctx *ctx, const uint8_t *key, size_t key_len)
{
    if (!ctx || !key) {
        return -1;
    }
    if (key_len != SKIPJACK_KEY_SIZE) {
        return -1;
    }

    /* Crypto++ builds tables from reversed key order; mirror it for compatibility. */
    for (size_t i = 0; i < SKIPJACK_KEY_SIZE; i++) {
        ctx->key[i] = key[SKIPJACK_KEY_SIZE - 1 - i];
    }
    return 0;
}

void skipjack_encrypt_block(const skipjack_ctx *ctx, const uint8_t *in, uint8_t *out)
{
    uint16_t w4 = load_le16(in);
    uint16_t w3 = load_le16(in + 2);
    uint16_t w2 = load_le16(in + 4);
    uint16_t w1 = load_le16(in + 6);
    uint16_t tmp, tmp1;
    int x, kp;

    for (x = 1, kp = 0; x < 9; x++) {
        tmp = g_func(w1, &kp, ctx->key);
        w1 = (uint16_t)(tmp ^ w4 ^ x);
        w4 = w3;
        w3 = w2;
        w2 = tmp;
    }

    for (; x < 17; x++) {
        tmp = g_func(w1, &kp, ctx->key);
        tmp1 = w4;
        w4 = w3;
        w3 = (uint16_t)(w1 ^ w2 ^ x);
        w1 = tmp1;
        w2 = tmp;
    }

    for (; x < 25; x++) {
        tmp = g_func(w1, &kp, ctx->key);
        w1 = (uint16_t)(tmp ^ w4 ^ x);
        w4 = w3;
        w3 = w2;
        w2 = tmp;
    }

    for (; x < 33; x++) {
        tmp = g_func(w1, &kp, ctx->key);
        tmp1 = w4;
        w4 = w3;
        w3 = (uint16_t)(w1 ^ w2 ^ x);
        w1 = tmp1;
        w2 = tmp;
    }

    store_le16(out, w4);
    store_le16(out + 2, w3);
    store_le16(out + 4, w2);
    store_le16(out + 6, w1);
}

void skipjack_decrypt_block(const skipjack_ctx *ctx, const uint8_t *in, uint8_t *out)
{
    uint16_t w4 = load_le16(in);
    uint16_t w3 = load_le16(in + 2);
    uint16_t w2 = load_le16(in + 4);
    uint16_t w1 = load_le16(in + 6);
    uint16_t tmp;
    int x, kp;

    for (x = 32, kp = 8; x > 24; x--) {
        tmp = ig_func(w2, &kp, ctx->key);
        w2 = (uint16_t)(tmp ^ w3 ^ x);
        w3 = w4;
        w4 = w1;
        w1 = tmp;
    }

    for (; x > 16; x--) {
        tmp = (uint16_t)(w1 ^ w2 ^ x);
        w1 = ig_func(w2, &kp, ctx->key);
        w2 = w3;
        w3 = w4;
        w4 = tmp;
    }

    for (; x > 8; x--) {
        tmp = ig_func(w2, &kp, ctx->key);
        w2 = (uint16_t)(tmp ^ w3 ^ x);
        w3 = w4;
        w4 = w1;
        w1 = tmp;
    }

    for (; x > 0; x--) {
        tmp = (uint16_t)(w1 ^ w2 ^ x);
        w1 = ig_func(w2, &kp, ctx->key);
        w2 = w3;
        w3 = w4;
        w4 = tmp;
    }

    store_le16(out, w4);
    store_le16(out + 2, w3);
    store_le16(out + 4, w2);
    store_le16(out + 6, w1);
}

void skipjack_cbc_encrypt(const skipjack_ctx *ctx,
                          const uint8_t *iv,
                          const uint8_t *in,
                          uint8_t *out,
                          size_t len)
{
    uint8_t prev[SKIPJACK_BLOCK_SIZE];

    memcpy(prev, iv, sizeof(prev));

    for (size_t offset = 0; offset < len; offset += SKIPJACK_BLOCK_SIZE) {
        uint8_t block[SKIPJACK_BLOCK_SIZE];
        for (size_t i = 0; i < SKIPJACK_BLOCK_SIZE; i++) {
            block[i] = (uint8_t)(in[offset + i] ^ prev[i]);
        }
        skipjack_encrypt_block(ctx, block, out + offset);
        memcpy(prev, out + offset, SKIPJACK_BLOCK_SIZE);
    }
}

void skipjack_cbc_decrypt(const skipjack_ctx *ctx,
                          const uint8_t *iv,
                          const uint8_t *in,
                          uint8_t *out,
                          size_t len)
{
    uint8_t prev[SKIPJACK_BLOCK_SIZE];

    memcpy(prev, iv, sizeof(prev));

    for (size_t offset = 0; offset < len; offset += SKIPJACK_BLOCK_SIZE) {
        uint8_t block[SKIPJACK_BLOCK_SIZE];
        skipjack_decrypt_block(ctx, in + offset, block);
        for (size_t i = 0; i < SKIPJACK_BLOCK_SIZE; i++) {
            out[offset + i] = (uint8_t)(block[i] ^ prev[i]);
        }
        memcpy(prev, in + offset, SKIPJACK_BLOCK_SIZE);
    }
}
