/* instance_label=MARS-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0xec, 0xd9, 0xaf, 0x42, 0x59, 0xdd, 0x2c, 0x2e,
    0xc2, 0xd5, 0xc8, 0x02, 0xcb, 0xc2, 0x3a, 0x7c,
    0xd2, 0x3e, 0xfd, 0xcf, 0x08, 0x7e, 0xc8, 0xeb,
    0xfd, 0xac, 0xcf, 0xd7, 0xc6, 0x03, 0xdf, 0xb1
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
