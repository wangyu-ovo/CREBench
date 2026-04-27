/*
 * RC2 CBC demo implementation (standalone, no OpenSSL dependency).
 * For demo/educational purposes only; not constant-time and not hardened.
 */

#ifndef DEMO_RC2_H
#define DEMO_RC2_H

#include <stddef.h>
#include <stdint.h>

#define RC2_BLOCK_BYTES 8
#define RC2_KEY_LENGTH 16
#define RC2_ENCRYPT 1
#define RC2_DECRYPT 0

typedef unsigned int RC2_INT;

typedef struct demo_rc2_key_st {
    RC2_INT data[64];
} DEMO_RC2_KEY;

typedef struct {
    DEMO_RC2_KEY key;
    int key_bytes;
    int effective_key_bits; /* typically key_bytes * 8 */
} rc2_ctx;

/* Internal functions */
void demo_RC2_set_key(DEMO_RC2_KEY *key, int len, const unsigned char *data, int bits);
void demo_RC2_encrypt(unsigned long *d, DEMO_RC2_KEY *key);
void demo_RC2_decrypt(unsigned long *d, DEMO_RC2_KEY *key);

/* Key schedule and block encrypt */
void rc2_key_set(rc2_ctx *ctx, const uint8_t *key, size_t key_bytes);
void rc2_encrypt_block(const rc2_ctx *ctx, const uint8_t in[RC2_BLOCK_BYTES], uint8_t out[RC2_BLOCK_BYTES]);

/* CBC encrypt: in/out can alias, len must be multiple of 8 */
void rc2_cbc_encrypt(const rc2_ctx *ctx,
                     const uint8_t *iv,
                     const uint8_t *in,
                     uint8_t *out,
                     size_t len);

#endif /* DEMO_RC2_H */