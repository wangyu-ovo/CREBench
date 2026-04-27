/*
 * RC6 Block Cipher (RC6-32/20/16) - C implementation
 *
 * Block size: 128 bits (16 bytes)
 * Key size: 128/192/256 bits (16/24/32 bytes)
 * Rounds: 20
 */
#ifndef RC6_H
#define RC6_H

#include <stddef.h>
#include <stdint.h>

#define RC6_BLOCK_SIZE 16
#define RC6_ROUNDS 20
#define RC6_MAX_KEY_SIZE 32

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t s[2 * (RC6_ROUNDS + 2)];
    unsigned int rounds;
} rc6_ctx;

int rc6_set_key(rc6_ctx *ctx, const uint8_t *key, size_t key_len);

void rc6_encrypt_block(const rc6_ctx *ctx, const uint8_t *in, uint8_t *out);
void rc6_decrypt_block(const rc6_ctx *ctx, const uint8_t *in, uint8_t *out);

void rc6_cbc_encrypt(const rc6_ctx *ctx,
                     const uint8_t *iv,
                     const uint8_t *in,
                     uint8_t *out,
                     size_t len);

void rc6_cbc_decrypt(const rc6_ctx *ctx,
                     const uint8_t *iv,
                     const uint8_t *in,
                     uint8_t *out,
                     size_t len);

#ifdef __cplusplus
}
#endif

#endif /* RC6_H */
