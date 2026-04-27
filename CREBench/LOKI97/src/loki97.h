/*
 * Adapted for CREBench from the public LOKI97 reference implementations.
 *
 * Credits:
 *   LOKI97 was written by Lawrie Brown, Josef Pieprzyk, and Jennifer Seberry.
 *   Copyright (c) 1998 by Lawrie Brown and ITRACE (UNSW).
 *   All rights reserved.
 *
 * LOKI97 Block Cipher - C implementation
 *
 * Block size: 128 bits (16 bytes)
 * Key size: 128/192/256 bits (16/24/32 bytes)
 */
#ifndef LOKI97_H
#define LOKI97_H

#include <stddef.h>
#include <stdint.h>

#define LOKI97_BLOCK_SIZE 16
#define LOKI97_MAX_KEY_SIZE 32

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t l;
    uint32_t r;
} loki97_u64;

typedef struct {
    loki97_u64 sk[48];
} loki97_ctx;

int loki97_set_key(loki97_ctx *ctx, const uint8_t *key, size_t key_len);

void loki97_encrypt_block(const loki97_ctx *ctx, const uint8_t *in, uint8_t *out);
void loki97_decrypt_block(const loki97_ctx *ctx, const uint8_t *in, uint8_t *out);

void loki97_cbc_encrypt(const loki97_ctx *ctx,
                        const uint8_t *iv,
                        const uint8_t *in,
                        uint8_t *out,
                        size_t len);

void loki97_cbc_decrypt(const loki97_ctx *ctx,
                        const uint8_t *iv,
                        const uint8_t *in,
                        uint8_t *out,
                        size_t len);

#ifdef __cplusplus
}
#endif

#endif /* LOKI97_H */
