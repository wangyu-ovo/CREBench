#ifndef E0_H
#define E0_H

#include <stddef.h>
#include <stdint.h>

#define E0_KEY_BYTES 16
#define E0_IV_BYTES 10

void e0_crypt(
    const uint8_t key[E0_KEY_BYTES],
    const uint8_t iv[E0_IV_BYTES],
    const uint8_t *input,
    uint8_t *output,
    size_t len
);

#endif
