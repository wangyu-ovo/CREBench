/*
 * CAST5 (CAST-128) Block Cipher (CBC mode)
 *
 * Block size: 64 bits (8 bytes)
 * Key size:  40-128 bits (5-16 bytes)
 */
#ifndef CAST5_H
#define CAST5_H

#include <stddef.h>
#include <stdint.h>

#define CAST5_BLOCK_SIZE 8
#define CAST5_MIN_KEY_SIZE 5
#define CAST5_MAX_KEY_SIZE 16

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t subkeys[32]; /* Km[0..15], Kr[0..15] */
    unsigned int rounds;
} cast5_ctx;

int cast5_set_key(cast5_ctx *ctx, const uint8_t *key, size_t key_len);

void cast5_encrypt_block(const cast5_ctx *ctx, const uint8_t *in, uint8_t *out);
void cast5_decrypt_block(const cast5_ctx *ctx, const uint8_t *in, uint8_t *out);

void cast5_cbc_encrypt(const cast5_ctx *ctx,
                       const uint8_t *iv,
                       const uint8_t *in,
                       uint8_t *out,
                       size_t len);

void cast5_cbc_decrypt(const cast5_ctx *ctx,
                       const uint8_t *iv,
                       const uint8_t *in,
                       uint8_t *out,
                       size_t len);

#ifdef __cplusplus
}
#endif

#endif /* CAST5_H */
