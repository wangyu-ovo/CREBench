/*
 * Minimal SM4 implementation based on OpenSSL.
 * Public domain style for demo purposes only; not constant-time.
 */

#include <string.h>
#include "sm4.h"

#ifdef CONSTXOR_SM4_TABLES
#include "constxor_tables.h"
#define SM4_SBOX_TABLE (constxor_sm4_sbox())
#define SM4_FK_TABLE (constxor_sm4_fk())
#define SM4_CK_TABLE (constxor_sm4_ck())
#else
/* SM4 S-box */
static const uint8_t SM4_S[256] = {
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2,
    0x28, 0xFB, 0x2C, 0x05, 0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3,
    0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9C, 0x42, 0x50, 0xF4,
    0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA,
    0x75, 0x8F, 0x3F, 0xA6, 0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA,
    0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8, 0x68, 0x6B, 0x81, 0xB2,
    0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B,
    0x01, 0x21, 0x78, 0x87, 0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52,
    0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E, 0xEA, 0xBF, 0x8A, 0xD2,
    0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30,
    0xF5, 0x8C, 0xB1, 0xE3, 0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60,
    0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F, 0xD5, 0xDB, 0x37, 0x45,
    0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41,
    0x1F, 0x10, 0x5A, 0xD8, 0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD,
    0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0, 0x89, 0x69, 0x97, 0x4A,
    0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E,
    0xD7, 0xCB, 0x39, 0x48
};

/* Family Key */
static const uint32_t FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

/* Constant Key */
static const uint32_t CK[32] = {
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};
#define SM4_SBOX_TABLE (SM4_S)
#define SM4_FK_TABLE (FK)
#define SM4_CK_TABLE (CK)
#endif

static inline uint32_t rotl(uint32_t a, uint8_t n) {
    return (a << n) | (a >> (32 - n));
}

static inline uint32_t load_u32_be(const uint8_t *b, uint32_t n) {
    return ((uint32_t)b[4 * n] << 24) |
           ((uint32_t)b[4 * n + 1] << 16) |
           ((uint32_t)b[4 * n + 2] << 8) |
           ((uint32_t)b[4 * n + 3]);
}

static inline void store_u32_be(uint32_t v, uint8_t *b) {
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)(v);
}

static inline uint32_t SM4_T_non_lin_sub(uint32_t X) {
    uint32_t t = 0;

    t |= ((uint32_t)SM4_SBOX_TABLE[(uint8_t)(X >> 24)]) << 24;
    t |= ((uint32_t)SM4_SBOX_TABLE[(uint8_t)(X >> 16)]) << 16;
    t |= ((uint32_t)SM4_SBOX_TABLE[(uint8_t)(X >> 8)]) << 8;
    t |= SM4_SBOX_TABLE[(uint8_t)X];

    return t;
}

static inline uint32_t SM4_T_slow(uint32_t X) {
    uint32_t t = SM4_T_non_lin_sub(X);

    /* L linear transform */
    return t ^ rotl(t, 2) ^ rotl(t, 10) ^ rotl(t, 18) ^ rotl(t, 24);
}

static inline uint32_t SM4_key_sub(uint32_t X) {
    uint32_t t = SM4_T_non_lin_sub(X);

    return t ^ rotl(t, 13) ^ rotl(t, 23);
}

static __attribute__((noinline)) void sm4_key_expand_impl(sm4_ctx *ctx,
                                                          const uint8_t key[SM4_KEY_BYTES]) {
    uint32_t K0;
    uint32_t K1;
    uint32_t K2;
    uint32_t K3;

    K0 = load_u32_be(key, 0) ^ SM4_FK_TABLE[0];
    K1 = load_u32_be(key, 1) ^ SM4_FK_TABLE[1];
    K2 = load_u32_be(key, 2) ^ SM4_FK_TABLE[2];
    K3 = load_u32_be(key, 3) ^ SM4_FK_TABLE[3];

    for (int i = 0; i < SM4_KEY_SCHEDULE; i += 4) {
        K0 ^= SM4_key_sub(K1 ^ K2 ^ K3 ^ SM4_CK_TABLE[i]);
        K1 ^= SM4_key_sub(K2 ^ K3 ^ K0 ^ SM4_CK_TABLE[i + 1]);
        K2 ^= SM4_key_sub(K3 ^ K0 ^ K1 ^ SM4_CK_TABLE[i + 2]);
        K3 ^= SM4_key_sub(K0 ^ K1 ^ K2 ^ SM4_CK_TABLE[i + 3]);
        ctx->rk[i] = K0;
        ctx->rk[i + 1] = K1;
        ctx->rk[i + 2] = K2;
        ctx->rk[i + 3] = K3;
    }
}

void sm4_key_expand(sm4_ctx *ctx, const uint8_t key[SM4_KEY_BYTES]) {
    sm4_key_expand_impl(ctx, key);
}

#define SM4_RNDS(k0, k1, k2, k3, F)          \
      do {                                   \
         B0 ^= F(B1 ^ B2 ^ B3 ^ ctx->rk[k0]); \
         B1 ^= F(B0 ^ B2 ^ B3 ^ ctx->rk[k1]); \
         B2 ^= F(B0 ^ B1 ^ B3 ^ ctx->rk[k2]); \
         B3 ^= F(B0 ^ B1 ^ B2 ^ ctx->rk[k3]); \
      } while(0)

void sm4_encrypt_block(const sm4_ctx *ctx, const uint8_t in[SM4_BLOCK_BYTES], uint8_t out[SM4_BLOCK_BYTES]) {
    uint32_t B0 = load_u32_be(in, 0);
    uint32_t B1 = load_u32_be(in, 1);
    uint32_t B2 = load_u32_be(in, 2);
    uint32_t B3 = load_u32_be(in, 3);

    /*
     * Uses byte-wise sbox in the first and last rounds to provide some
     * protection from cache based side channels.
     */
    SM4_RNDS( 0,  1,  2,  3, SM4_T_slow);
    SM4_RNDS( 4,  5,  6,  7, SM4_T_slow);
    SM4_RNDS( 8,  9, 10, 11, SM4_T_slow);
    SM4_RNDS(12, 13, 14, 15, SM4_T_slow);
    SM4_RNDS(16, 17, 18, 19, SM4_T_slow);
    SM4_RNDS(20, 21, 22, 23, SM4_T_slow);
    SM4_RNDS(24, 25, 26, 27, SM4_T_slow);
    SM4_RNDS(28, 29, 30, 31, SM4_T_slow);

    store_u32_be(B3, out);
    store_u32_be(B2, out + 4);
    store_u32_be(B1, out + 8);
    store_u32_be(B0, out + 12);
}

void sm4_decrypt_block(const sm4_ctx *ctx, const uint8_t in[SM4_BLOCK_BYTES], uint8_t out[SM4_BLOCK_BYTES]) {
    uint32_t B0 = load_u32_be(in, 0);
    uint32_t B1 = load_u32_be(in, 1);
    uint32_t B2 = load_u32_be(in, 2);
    uint32_t B3 = load_u32_be(in, 3);

    SM4_RNDS(31, 30, 29, 28, SM4_T_slow);
    SM4_RNDS(27, 26, 25, 24, SM4_T_slow);
    SM4_RNDS(23, 22, 21, 20, SM4_T_slow);
    SM4_RNDS(19, 18, 17, 16, SM4_T_slow);
    SM4_RNDS(15, 14, 13, 12, SM4_T_slow);
    SM4_RNDS(11, 10,  9,  8, SM4_T_slow);
    SM4_RNDS( 7,  6,  5,  4, SM4_T_slow);
    SM4_RNDS( 3,  2,  1,  0, SM4_T_slow);

    store_u32_be(B3, out);
    store_u32_be(B2, out + 4);
    store_u32_be(B1, out + 8);
    store_u32_be(B0, out + 12);
}

void sm4_cbc_encrypt(const sm4_ctx *ctx, const uint8_t *iv, const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t iv_copy[SM4_BLOCK_BYTES];
    memcpy(iv_copy, iv, SM4_BLOCK_BYTES);

    for (size_t i = 0; i < len; i += SM4_BLOCK_BYTES) {
        /* XOR with IV */
        for (int j = 0; j < SM4_BLOCK_BYTES; j++) {
            iv_copy[j] ^= in[i + j];
        }

        /* Encrypt */
        sm4_encrypt_block(ctx, iv_copy, out + i);

        /* Update IV */
        memcpy(iv_copy, out + i, SM4_BLOCK_BYTES);
    }
}

void sm4_cbc_decrypt(const sm4_ctx *ctx, const uint8_t *iv, const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t iv_copy[SM4_BLOCK_BYTES];
    uint8_t block[SM4_BLOCK_BYTES];
    memcpy(iv_copy, iv, SM4_BLOCK_BYTES);

    for (size_t i = 0; i < len; i += SM4_BLOCK_BYTES) {
        /* Save ciphertext for IV update */
        memcpy(block, in + i, SM4_BLOCK_BYTES);

        /* Decrypt */
        sm4_decrypt_block(ctx, in + i, out + i);

        /* XOR with IV */
        for (int j = 0; j < SM4_BLOCK_BYTES; j++) {
            out[i + j] ^= iv_copy[j];
        }

        /* Update IV */
        memcpy(iv_copy, block, SM4_BLOCK_BYTES);
    }
}
