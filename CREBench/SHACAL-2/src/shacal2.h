/*
 * Adapted for CREBench from SHACAL-2 reference implementations.
 *
 * Main references:
 *   - Crypto++:
 *       shacal2.cpp - written by Kevin Springle (2003)
 *       portions derived from Wei Dai's SHA-2 implementation
 *       original code and modifications released to the public domain
 *   - Botan:
 *       (C) 2017,2020 Jack Lloyd
 *       Botan is released under the Simplified BSD License
 *
 * SHACAL-2 Block Cipher (CBC mode)
 *
 * Block size: 256 bits (32 bytes)
 * Key size:   128-512 bits (16-64 bytes, 4-byte increments)
 */
#ifndef SHACAL2_H
#define SHACAL2_H

#include <stddef.h>
#include <stdint.h>

#define SHACAL2_BLOCK_SIZE 32
#define SHACAL2_MIN_KEY_SIZE 16
#define SHACAL2_MAX_KEY_SIZE 64

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t rk[64];
} shacal2_ctx;

int shacal2_set_key(shacal2_ctx *ctx, const uint8_t *key, size_t key_len);

void shacal2_encrypt_block(const shacal2_ctx *ctx, const uint8_t *in, uint8_t *out);
void shacal2_decrypt_block(const shacal2_ctx *ctx, const uint8_t *in, uint8_t *out);

void shacal2_cbc_encrypt(const shacal2_ctx *ctx,
                         const uint8_t *iv,
                         const uint8_t *in,
                         uint8_t *out,
                         size_t len);

void shacal2_cbc_decrypt(const shacal2_ctx *ctx,
                         const uint8_t *iv,
                         const uint8_t *in,
                         uint8_t *out,
                         size_t len);

#ifdef __cplusplus
}
#endif

#endif /* SHACAL2_H */
