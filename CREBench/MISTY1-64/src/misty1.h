/*
 * MISTY1 Block Cipher Implementation
 *
 * Based on RFC 2994: A Description of the MISTY1 Encryption Algorithm
 *
 * Reference implementation attribution:
 *   Copyright (C) 1998, Hironobu SUZUKI.
 *   Copyright Condition: GNU GENERAL PUBLIC LICENSE Version 2
 *
 * Block size: 64 bits (8 bytes)
 * Key size: 128 bits (16 bytes)
 * Rounds: 8
 */

#ifndef MISTY1_H
#define MISTY1_H

#include <stdint.h>
#include <stddef.h>

#define MISTY1_BLOCK_SIZE 8   /* 64-bit block */
#define MISTY1_KEY_SIZE   16  /* 128-bit key */
#define MISTY1_ROUNDS     8   /* 8 rounds */

/* Expanded key size: 32 x 16-bit values */
#define MISTY1_EK_SIZE    32

/* MISTY1 context structure */
typedef struct {
    uint16_t EK[MISTY1_EK_SIZE];  /* Expanded key schedule */
} misty1_ctx;

/* Initialize the MISTY1 key schedule */
int misty1_set_key(misty1_ctx *ctx, const uint8_t *key);

/* Encrypt a single 8-byte block */
void misty1_encrypt_block(const misty1_ctx *ctx, const uint8_t *in, uint8_t *out);

/* Decrypt a single 8-byte block */
void misty1_decrypt_block(const misty1_ctx *ctx, const uint8_t *in, uint8_t *out);

/* ECB mode encryption */
void misty1_ecb_encrypt(const misty1_ctx *ctx,
                        const uint8_t *in,
                        uint8_t *out,
                        size_t len);

/* ECB mode decryption */
void misty1_ecb_decrypt(const misty1_ctx *ctx,
                        const uint8_t *in,
                        uint8_t *out,
                        size_t len);

/* CBC mode encryption */
void misty1_cbc_encrypt(const misty1_ctx *ctx,
                        const uint8_t *iv,
                        const uint8_t *in,
                        uint8_t *out,
                        size_t len);

/* CBC mode decryption */
void misty1_cbc_decrypt(const misty1_ctx *ctx,
                        const uint8_t *iv,
                        const uint8_t *in,
                        uint8_t *out,
                        size_t len);

#endif /* MISTY1_H */

