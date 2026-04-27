/*
 * MAGENTA-128 Block Cipher (CBC mode)
 *
 * Block size: 128 bits (16 bytes)
 * Key size:   128 bits (16 bytes)
 */

#ifndef MAGENTA_H
#define MAGENTA_H

#include <stddef.h>
#include <stdint.h>

#define MAGENTA_BLOCK_SIZE 16
#define MAGENTA_KEY_SIZE 16

typedef struct {
    uint32_t l_key[12];
} magenta_ctx;

int magenta_set_key(magenta_ctx *ctx, const uint8_t *key, size_t key_len);

void magenta_cbc_encrypt(const magenta_ctx *ctx, const uint8_t *iv,
                         const uint8_t *in, uint8_t *out, size_t len);

void magenta_cbc_decrypt(const magenta_ctx *ctx, const uint8_t *iv,
                         const uint8_t *in, uint8_t *out, size_t len);

#endif /* MAGENTA_H */
