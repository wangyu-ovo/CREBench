/*
 * Minimal Blowfish implementation (ECB block) and CBC encrypt utility.
 * Public domain style for demo purposes only; not constant-time.
 */

#ifndef DEMO_BLOWFISH_H
#define DEMO_BLOWFISH_H

#include <stddef.h>
#include <stdint.h>

#define BF_BLOCK_BYTES 8
#define BF_ROUNDS 16

#define BF_LONG unsigned int

typedef struct {
    BF_LONG P[BF_ROUNDS + 2];
    BF_LONG S[4 * 256];
} bf_key;

/* Core Blowfish routines */
void bf_set_key(bf_key *key, int len, const uint8_t *data);
void bf_encrypt(BF_LONG *data, const bf_key *key);
void bf_decrypt(BF_LONG *data, const bf_key *key);

/* CBC encrypt: in/out can alias, len must be multiple of 8 */
void bf_cbc_encrypt(const bf_key *key,
                   const uint8_t *iv,
                   const uint8_t *in,
                   uint8_t *out,
                   size_t len);

#endif /* DEMO_BLOWFISH_H */
