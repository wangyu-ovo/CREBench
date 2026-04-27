/*
 * SAFER Block Cipher (SAFER-K/SK) - C implementation
 *
 * Block size: 64 bits (8 bytes)
 * Key size: 64 or 128 bits (8 or 16 bytes)
 * Rounds: default 6/10 for SAFER-K, 8/10 for SAFER-SK
 */
#ifndef SAFER_H
#define SAFER_H

#include <stddef.h>
#include <stdint.h>

#define SAFER_BLOCK_SIZE 8
#define SAFER_MAX_KEY_SIZE 16
#define SAFER_MAX_ROUNDS 13

#define SAFER_K64_DEFAULT_ROUNDS 6
#define SAFER_K128_DEFAULT_ROUNDS 10
#define SAFER_SK64_DEFAULT_ROUNDS 8
#define SAFER_SK128_DEFAULT_ROUNDS 10

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t key[1 + SAFER_BLOCK_SIZE * (1 + 2 * SAFER_MAX_ROUNDS)];
} safer_ctx;

/* SAFER-K key schedule (non-strengthened) */
int safer_set_key(safer_ctx *ctx, const uint8_t *key, size_t key_len);

/* SAFER-SK key schedule (strengthened) */
int safer_set_key_sk(safer_ctx *ctx, const uint8_t *key, size_t key_len);

/* Encrypt/decrypt a single 8-byte block */
void safer_encrypt_block(const safer_ctx *ctx, const uint8_t *in, uint8_t *out);
void safer_decrypt_block(const safer_ctx *ctx, const uint8_t *in, uint8_t *out);

/* CBC mode (no padding; length must be multiple of block size) */
void safer_cbc_encrypt(const safer_ctx *ctx,
                       const uint8_t *iv,
                       const uint8_t *in,
                       uint8_t *out,
                       size_t len);

void safer_cbc_decrypt(const safer_ctx *ctx,
                       const uint8_t *iv,
                       const uint8_t *in,
                       uint8_t *out,
                       size_t len);

#ifdef __cplusplus
}
#endif

#endif /* SAFER_H */
