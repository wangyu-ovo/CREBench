/*
 * Adapted from the GnuPG DES implementation.
 *
 * Original work:
 *   des.c - DES and Triple-DES encryption/decryption Algorithm
 *   Copyright (C) 1998 Free Software Foundation, Inc.
 *   Written by Michael Roth <mroth@nessie.de>, September 1998
 *
 * DES Block Cipher (CBC mode)
 *
 * Block size: 64 bits (8 bytes)
 * Key size:   64 bits (8 bytes, 56-bit effective)
 */

#ifndef DES_H
#define DES_H

#include <stddef.h>
#include <stdint.h>

#define DES_BLOCK_SIZE 8
#define DES_KEY_SIZE 8

typedef struct {
    uint8_t k[8];
    uint8_t c[4];
    uint8_t d[4];
} des_key_set;

typedef struct {
    des_key_set key_sets[17];
} des_ctx;

int des_set_key(des_ctx *ctx, const uint8_t *key);

void des_cbc_encrypt(const des_ctx *ctx, const uint8_t *iv,
                     const uint8_t *in, uint8_t *out, size_t len);

void des_cbc_decrypt(const des_ctx *ctx, const uint8_t *iv,
                     const uint8_t *in, uint8_t *out, size_t len);

#endif /* DES_H */
