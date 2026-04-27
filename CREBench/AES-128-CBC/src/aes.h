/*
 * Minimal AES-128 implementation (ECB block) and CBC encrypt utility.
 * Public domain style for demo purposes only; not constant-time.
 */

#ifndef DEMO_AES_H
#define DEMO_AES_H

#include <stddef.h>
#include <stdint.h>

#define AES128_KEY_BYTES 16
#define AES_BLOCK_BYTES 16

typedef struct {
    uint32_t round_keys[44]; /* 11 * 4 words */
} aes128_ctx;

/* Core AES-128 routines */
void aes128_key_expand(aes128_ctx *ctx, const uint8_t key[AES128_KEY_BYTES]);
void aes128_encrypt_block(const aes128_ctx *ctx, const uint8_t in[AES_BLOCK_BYTES], uint8_t out[AES_BLOCK_BYTES]);

/* CBC encrypt: in/out can alias, len must be multiple of 16 */
void aes128_cbc_encrypt(const aes128_ctx *ctx,
                        const uint8_t *iv,
                        const uint8_t *in,
                        uint8_t *out,
                        size_t len);

#endif /* DEMO_AES_H */


