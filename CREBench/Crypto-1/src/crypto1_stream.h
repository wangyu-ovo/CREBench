#ifndef CRYPTO1_STREAM_H
#define CRYPTO1_STREAM_H

#include <stddef.h>
#include <stdint.h>

#define CRYPTO1_KEY_BYTES 6
#define CRYPTO1_IV_BYTES 8

void crypto1_crypt(
    const uint8_t key[CRYPTO1_KEY_BYTES],
    const uint8_t iv[CRYPTO1_IV_BYTES],
    const uint8_t *input,
    uint8_t *output,
    size_t len
);

#endif
