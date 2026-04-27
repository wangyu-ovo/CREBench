/*
 * Adapted for CREBench from public MARS implementations.
 *
 * Reference attributions:
 *   - Crypto++ MARS implementation:
 *       Copyright and public-domain notice by Wei Dai
 *   - Brian Gladman reference implementation:
 *       Copyright held by Dr Brian Gladman (1998), with permission
 *       for free direct or derivative use subject to acknowledgment
 *       and IBM MARS usage constraints.
 *
 * MARS Block Cipher (CBC mode)
 *
 * Block size: 128 bits (16 bytes)
 * Key size:   128-448 bits (16-56 bytes)
 */
#ifndef MARS_H
#define MARS_H

#include <stddef.h>
#include <stdint.h>

#define MARS_BLOCK_SIZE 16
#define MARS_MIN_KEY_SIZE 16
#define MARS_MAX_KEY_SIZE 56

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t k[40];
} mars_ctx;

int mars_set_key(mars_ctx *ctx, const uint8_t *key, size_t key_len);

void mars_encrypt_block(const mars_ctx *ctx, const uint8_t *in, uint8_t *out);
void mars_decrypt_block(const mars_ctx *ctx, const uint8_t *in, uint8_t *out);

void mars_cbc_encrypt(const mars_ctx *ctx,
                      const uint8_t *iv,
                      const uint8_t *in,
                      uint8_t *out,
                      size_t len);

void mars_cbc_decrypt(const mars_ctx *ctx,
                      const uint8_t *iv,
                      const uint8_t *in,
                      uint8_t *out,
                      size_t len);

#ifdef __cplusplus
}
#endif

#endif /* MARS_H */
