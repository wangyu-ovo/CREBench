#ifndef CHACHA20_H
#define CHACHA20_H

#include <stddef.h>
#include <stdint.h>

#define CHACHA20_KEY_BYTES 32
#define CHACHA20_NONCE_BYTES 12
#define CHACHA20_BLOCK_BYTES 64

void chacha20_crypt(
    const uint8_t key[CHACHA20_KEY_BYTES],
    const uint8_t nonce[CHACHA20_NONCE_BYTES],
    uint32_t counter,
    const uint8_t *input,
    uint8_t *output,
    size_t len
);

#endif /* CHACHA20_H */

