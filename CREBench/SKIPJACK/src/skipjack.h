/*
 * SKIPJACK Block Cipher - C implementation
 *
 * Block size: 64 bits (8 bytes)
 * Key size: 80 bits (10 bytes)
 */
#ifndef SKIPJACK_H
#define SKIPJACK_H

#include <stddef.h>
#include <stdint.h>

#define SKIPJACK_BLOCK_SIZE 8
#define SKIPJACK_KEY_SIZE 10

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t key[SKIPJACK_KEY_SIZE];
} skipjack_ctx;

int skipjack_set_key(skipjack_ctx *ctx, const uint8_t *key, size_t key_len);

void skipjack_encrypt_block(const skipjack_ctx *ctx, const uint8_t *in, uint8_t *out);
void skipjack_decrypt_block(const skipjack_ctx *ctx, const uint8_t *in, uint8_t *out);

void skipjack_cbc_encrypt(const skipjack_ctx *ctx,
                          const uint8_t *iv,
                          const uint8_t *in,
                          uint8_t *out,
                          size_t len);

void skipjack_cbc_decrypt(const skipjack_ctx *ctx,
                          const uint8_t *iv,
                          const uint8_t *in,
                          uint8_t *out,
                          size_t len);

#ifdef __cplusplus
}
#endif

#endif /* SKIPJACK_H */
