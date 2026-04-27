#ifndef RC4_H
#define RC4_H

#include <stddef.h>
#include <stdint.h>

#define RC4_KEY_BYTES 16

typedef struct {
    uint8_t s[256];
    uint8_t i;
    uint8_t j;
} rc4_ctx;

void rc4_init(rc4_ctx *ctx, const uint8_t *key, size_t key_len);
void rc4_crypt(rc4_ctx *ctx, const uint8_t *input, uint8_t *output, size_t len);

#endif /* RC4_H */

