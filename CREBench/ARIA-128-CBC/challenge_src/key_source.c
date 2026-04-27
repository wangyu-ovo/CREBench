/* instance_label=ARIA-128-CBC-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0xb8, 0xf2, 0x23, 0xef, 0xb3, 0x9c, 0xd9, 0x61,
    0x1f, 0xa3, 0xff, 0xd0, 0xc7, 0x73, 0xd3, 0x9e
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
