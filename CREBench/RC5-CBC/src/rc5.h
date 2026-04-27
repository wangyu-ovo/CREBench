/*
 * RC5 Block Cipher Implementation
 * 
 * RC5 is a symmetric block cipher designed by Ronald Rivest in 1994.
 * It uses variable block size, key size, and number of rounds.
 * 
 * This implementation uses RC5-32/12/16 (32-bit words, 12 rounds, 16-byte key)
 * which is compatible with OpenSSL's default RC5 settings.
 * 
 * Block size: 64 bits (8 bytes)
 * Key size: 0-255 bytes (default 16 bytes = 128 bits)
 * Rounds: variable (default 12 for OpenSSL compatibility)
 * 
 * For educational and CTF purposes only.
 */
#ifndef RC5_H
#define RC5_H

#include <stdint.h>
#include <stddef.h>

#define RC5_BLOCK_SIZE  8       /* 64 bits = 8 bytes */
#define RC5_DEFAULT_ROUNDS 12   /* Default rounds (OpenSSL uses 12) */
#define RC5_MAX_ROUNDS 255
#define RC5_MAX_KEY_SIZE 255

/* Magic constants for 32-bit words */
#define RC5_P32 0xB7E15163UL
#define RC5_Q32 0x9E3779B9UL

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t S[2 * (RC5_MAX_ROUNDS + 1)];  /* Expanded key table */
    unsigned int rounds;                     /* Number of rounds */
} rc5_ctx;

/* Initialize context with key */
int rc5_set_key(rc5_ctx *ctx, const uint8_t *key, size_t key_len, unsigned int rounds);

/* Encrypt a single 8-byte block */
void rc5_encrypt_block(const rc5_ctx *ctx, const uint8_t *in, uint8_t *out);

/* Decrypt a single 8-byte block */
void rc5_decrypt_block(const rc5_ctx *ctx, const uint8_t *in, uint8_t *out);

/* CBC mode encryption */
void rc5_cbc_encrypt(const rc5_ctx *ctx,
                     const uint8_t *iv,
                     const uint8_t *in,
                     uint8_t *out,
                     size_t len);

/* CBC mode decryption */
void rc5_cbc_decrypt(const rc5_ctx *ctx,
                     const uint8_t *iv,
                     const uint8_t *in,
                     uint8_t *out,
                     size_t len);

#ifdef __cplusplus
}
#endif

#endif /* RC5_H */

