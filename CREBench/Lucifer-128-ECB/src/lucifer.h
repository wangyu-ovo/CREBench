/*
 * LUCIFER Block Cipher
 * 
 * LUCIFER is a block cipher developed by IBM in the early 1970s.
 * It was a predecessor to DES and uses a 128-bit block size with a 128-bit key.
 * 
 * Based on Arthur Sorkin's CRYPTOLOGIA article (Volume 8, Number 1, January 1984)
 * and the reference implementations from lucifer-go and cryptospecs.
 * 
 * For educational and CTF purposes only.
 */
#ifndef LUCIFER_H
#define LUCIFER_H

#include <stdint.h>
#include <stddef.h>

#define LUCIFER_BLOCK_SIZE 16
#define LUCIFER_KEY_SIZE   16
#define LUCIFER_ROUNDS     16

#ifdef __cplusplus
extern "C" {
#endif

/* Key structure for Lucifer */
typedef struct {
    uint8_t key[16];          /* Original key bytes */
    uint8_t pkey[128];        /* Permuted key schedule */
    int is_decrypt;           /* 0 for encrypt, 1 for decrypt */
} lucifer_ctx;

/* Initialize context for encryption */
void lucifer_set_encrypt_key(lucifer_ctx *ctx, const uint8_t *key);

/* Initialize context for decryption */
void lucifer_set_decrypt_key(lucifer_ctx *ctx, const uint8_t *key);

/* Encrypt a single 16-byte block */
void lucifer_encrypt_block(lucifer_ctx *ctx, const uint8_t *in, uint8_t *out);

/* Decrypt a single 16-byte block */
void lucifer_decrypt_block(lucifer_ctx *ctx, const uint8_t *in, uint8_t *out);

/* ECB mode encryption for multiple blocks */
void lucifer_ecb_encrypt(lucifer_ctx *ctx, const uint8_t *in, uint8_t *out, size_t len);

/* ECB mode decryption for multiple blocks */
void lucifer_ecb_decrypt(lucifer_ctx *ctx, const uint8_t *in, uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* LUCIFER_H */

