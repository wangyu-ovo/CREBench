/*
 * KHAZAD Block Cipher Implementation
 *
 * KHAZAD is a block cipher designed by Paulo S.L.M. Barreto and Vincent Rijmen.
 * It was submitted to the NESSIE project.
 *
 * Block size: 64 bits (8 bytes)
 * Key size:   128 bits (16 bytes)
 * Rounds:     8
 *
 * For educational and CTF purposes only.
 */
#ifndef KHAZAD_H
#define KHAZAD_H

#include <stdint.h>
#include <stddef.h>

#define KHAZAD_BLOCK_SIZE   8   /* 64 bits = 8 bytes */
#define KHAZAD_KEY_SIZE    16   /* 128 bits = 16 bytes */
#define KHAZAD_ROUNDS       8

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t roundKeyEnc[KHAZAD_ROUNDS + 1];  /* Encryption round keys */
    uint64_t roundKeyDec[KHAZAD_ROUNDS + 1];  /* Decryption round keys */
} our_khazad_ctx;

/* Initialize context with key */
int our_khazad_set_key(our_khazad_ctx *ctx, const uint8_t *key);

/* Encrypt a single 8-byte block */
void our_khazad_encrypt_block(const our_khazad_ctx *ctx, const uint8_t *in, uint8_t *out);

/* Decrypt a single 8-byte block */
void our_khazad_decrypt_block(const our_khazad_ctx *ctx, const uint8_t *in, uint8_t *out);

/* ECB mode encryption (for multiple blocks, len must be multiple of 8) */
void our_khazad_ecb_encrypt(const our_khazad_ctx *ctx,
                            const uint8_t *in,
                            uint8_t *out,
                            size_t len);

/* ECB mode decryption (for multiple blocks, len must be multiple of 8) */
void our_khazad_ecb_decrypt(const our_khazad_ctx *ctx,
                            const uint8_t *in,
                            uint8_t *out,
                            size_t len);

#ifdef __cplusplus
}
#endif

#endif /* KHAZAD_H */

