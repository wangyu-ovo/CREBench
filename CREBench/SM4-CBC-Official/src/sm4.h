/*
 * Minimal SM4 implementation (ECB block) and CBC encrypt utility.
 * Public domain style for demo purposes only; not constant-time.
 */

#ifndef DEMO_SM4_H
#define DEMO_SM4_H

#include <stddef.h>
#include <stdint.h>

#define SM4_KEY_BYTES 16
#define SM4_BLOCK_BYTES 16
#define SM4_KEY_SCHEDULE 32

typedef struct {
    uint32_t rk[SM4_KEY_SCHEDULE];
} sm4_ctx;

/* Core SM4 routines */
void sm4_key_expand(sm4_ctx *ctx, const uint8_t key[SM4_KEY_BYTES]);
void sm4_encrypt_block(const sm4_ctx *ctx, const uint8_t in[SM4_BLOCK_BYTES], uint8_t out[SM4_BLOCK_BYTES]);
void sm4_decrypt_block(const sm4_ctx *ctx, const uint8_t in[SM4_BLOCK_BYTES], uint8_t out[SM4_BLOCK_BYTES]);

/* CBC encrypt/decrypt: in/out can alias, len must be multiple of 16 */
void sm4_cbc_encrypt(const sm4_ctx *ctx,
                     const uint8_t *iv,
                     const uint8_t *in,
                     uint8_t *out,
                     size_t len);

void sm4_cbc_decrypt(const sm4_ctx *ctx,
                     const uint8_t *iv,
                     const uint8_t *in,
                     uint8_t *out,
                     size_t len);

#endif /* DEMO_SM4_H */
