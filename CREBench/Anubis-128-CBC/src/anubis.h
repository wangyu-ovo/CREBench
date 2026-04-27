/*
 * ANUBIS Block Cipher Implementation
 * 
 * ANUBIS is a block cipher designed by Vincent Rijmen and Paulo S.L.M. Barreto.
 * It operates on 128-bit blocks with 128-320 bit keys (in 32-bit steps).
 * 
 * For educational and CTF purposes only.
 */
#ifndef ANUBIS_H
#define ANUBIS_H

#include <stdint.h>
#include <stddef.h>

#define ANUBIS_BLOCK_SIZE 16
#define ANUBIS_MIN_KEY_SIZE 16   /* 128 bits */
#define ANUBIS_MAX_KEY_SIZE 40   /* 320 bits */
#define ANUBIS_MAX_ROUNDS 18     /* 8 + key_words, max = 8 + 10 = 18 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t roundKeyEnc[ANUBIS_MAX_ROUNDS + 1][4];
    uint32_t roundKeyDec[ANUBIS_MAX_ROUNDS + 1][4];
    int rounds;
} anubis_ctx;

/* Initialize context with key */
int anubis_set_key(anubis_ctx *ctx, const uint8_t *key, size_t key_len);

/* Encrypt a single 16-byte block */
void anubis_encrypt_block(const anubis_ctx *ctx, const uint8_t *in, uint8_t *out);

/* Decrypt a single 16-byte block */
void anubis_decrypt_block(const anubis_ctx *ctx, const uint8_t *in, uint8_t *out);

/* CBC mode encryption */
void anubis_cbc_encrypt(const anubis_ctx *ctx,
                        const uint8_t *iv,
                        const uint8_t *in,
                        uint8_t *out,
                        size_t len);

/* CBC mode decryption */
void anubis_cbc_decrypt(const anubis_ctx *ctx,
                        const uint8_t *iv,
                        const uint8_t *in,
                        uint8_t *out,
                        size_t len);

#ifdef __cplusplus
}
#endif

#endif /* ANUBIS_H */

