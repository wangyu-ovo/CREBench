/*
 * Adapted for CREBench from public NOEKEON references.
 *
 * Reference attributions:
 *   - NESSIE NOEKEON reference implementation (NoekeonIndirectRef.c):
 *       Authors: Joan Daemen, Michael Peeters, Vincent Rijmen, Gilles Van Assche
 *       Written by Michael Peeters
 *   - Botan implementation:
 *       (C) 1999-2008 Jack Lloyd
 *       Botan is released under the Simplified BSD License
 *
 * NOEKEON Block Cipher (CBC mode)
 *
 * Block size: 128 bits (16 bytes)
 * Key size:   128 bits (16 bytes)
 */
#ifndef NOEKEON_H
#define NOEKEON_H

#include <stddef.h>
#include <stdint.h>

#define NOEKEON_BLOCK_SIZE 16
#define NOEKEON_KEY_SIZE 16

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t k[4];
    uint32_t dk[4];
} noekeon_ctx;

int noekeon_set_key(noekeon_ctx *ctx, const uint8_t *key, size_t key_len);

void noekeon_encrypt_block(const noekeon_ctx *ctx, const uint8_t *in, uint8_t *out);
void noekeon_decrypt_block(const noekeon_ctx *ctx, const uint8_t *in, uint8_t *out);

void noekeon_cbc_encrypt(const noekeon_ctx *ctx,
                         const uint8_t *iv,
                         const uint8_t *in,
                         uint8_t *out,
                         size_t len);

void noekeon_cbc_decrypt(const noekeon_ctx *ctx,
                         const uint8_t *iv,
                         const uint8_t *in,
                         uint8_t *out,
                         size_t len);

#ifdef __cplusplus
}
#endif

#endif /* NOEKEON_H */
