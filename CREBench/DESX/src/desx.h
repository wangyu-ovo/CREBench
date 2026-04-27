/*
 * Adapted for CREBench from RSAREF DES sources.
 *
 * Original reference:
 *   DESC.C - Data Encryption Standard routines for RSAREF
 *   Based on "Karn/Hoey/Outerbridge" implementation (KHODES)
 *
 * DESX Block Cipher (CBC mode)
 *
 * Block size: 64 bits (8 bytes)
 * Key size:   192 bits (24 bytes)
 * Layout: DES key (8) + pre-whitening (8) + post-whitening (8)
 */

#ifndef DESX_H
#define DESX_H

#include <stddef.h>
#include <stdint.h>

#define DESX_BLOCK_SIZE 8
#define DESX_KEY_SIZE 24

typedef struct {
    uint8_t k[8];
    uint8_t c[4];
    uint8_t d[4];
} desx_key_set;

typedef struct {
    desx_key_set key_sets[17];
    uint8_t pre_whitening[DESX_BLOCK_SIZE];
    uint8_t post_whitening[DESX_BLOCK_SIZE];
} desx_ctx;

int desx_set_key(desx_ctx *ctx, const uint8_t *key, size_t key_len);

void desx_cbc_encrypt(const desx_ctx *ctx, const uint8_t *iv,
                      const uint8_t *in, uint8_t *out, size_t len);

void desx_cbc_decrypt(const desx_ctx *ctx, const uint8_t *iv,
                      const uint8_t *in, uint8_t *out, size_t len);

#endif /* DESX_H */
