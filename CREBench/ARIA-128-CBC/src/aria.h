/*
 * Complete ARIA-128 implementation
 * For educational purposes only; not constant-time and not hardened.
 */

#ifndef ARIA_H
#define ARIA_H

#include <stddef.h>
#include <stdint.h>

#define ARIA_BLOCK_SIZE 16
#define ARIA_MAX_KEYS 17

typedef union {
    unsigned char c[ARIA_BLOCK_SIZE];
    unsigned int u[ARIA_BLOCK_SIZE / sizeof(unsigned int)];
} ARIA_u128;

typedef unsigned char ARIA_c128[ARIA_BLOCK_SIZE];

struct aria_key_st {
    ARIA_u128 rd_key[ARIA_MAX_KEYS];
    unsigned int rounds;
};
typedef struct aria_key_st ARIA_KEY;

/* Key schedule and block encrypt */
int aria_set_encrypt_key(const unsigned char *userKey, const int bits, ARIA_KEY *key);
void aria_encrypt(const unsigned char *in, unsigned char *out, const ARIA_KEY *key);

/* CBC encrypt: in/out can alias, len must be multiple of 16 */
void aria_cbc_encrypt(const ARIA_KEY *key,
                      const unsigned char *iv,
                      const unsigned char *in,
                      unsigned char *out,
                      size_t len);

#endif /* ARIA_H */



