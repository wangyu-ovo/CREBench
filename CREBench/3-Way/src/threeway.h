/*
 * 3-Way Block Cipher Implementation
 *
 * Based on Joan Daemen's 3-Way cipher and the public-domain
 * reference used in Crypto++.
 *
 * Block size: 96 bits (12 bytes)
 * Key size:   96 bits (12 bytes)
 * Rounds:     11 (standard)
 */

#ifndef THREEWAY_H
#define THREEWAY_H

#include <stddef.h>
#include <stdint.h>

#define THREEWAY_BLOCK_SIZE 12
#define THREEWAY_KEY_SIZE 12
#define THREEWAY_ROUNDS 11

typedef struct {
    uint32_t k[3];
    unsigned int rounds;
} threeway_ctx;

int threeway_set_encrypt_key(threeway_ctx *ctx, const uint8_t *key, unsigned int rounds);
int threeway_set_decrypt_key(threeway_ctx *ctx, const uint8_t *key, unsigned int rounds);

void threeway_encrypt_block(const threeway_ctx *ctx, const uint8_t *in, uint8_t *out);
void threeway_decrypt_block(const threeway_ctx *ctx, const uint8_t *in, uint8_t *out);

void threeway_ecb_encrypt(const threeway_ctx *ctx, const uint8_t *in, uint8_t *out, size_t len);
void threeway_ecb_decrypt(const threeway_ctx *ctx, const uint8_t *in, uint8_t *out, size_t len);

void threeway_cbc_encrypt(const threeway_ctx *ctx, const uint8_t *iv,
                          const uint8_t *in, uint8_t *out, size_t len);
void threeway_cbc_decrypt(const threeway_ctx *ctx, const uint8_t *iv,
                          const uint8_t *in, uint8_t *out, size_t len);

#endif /* THREEWAY_H */
