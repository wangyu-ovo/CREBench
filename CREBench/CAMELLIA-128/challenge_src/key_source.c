/* instance_label=CAMELLIA-128-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x6f, 0x64, 0xd4, 0x3e, 0x4f, 0xf7, 0x69, 0xd8,
    0x87, 0x74, 0x8c, 0xf7, 0xc0, 0x2f, 0xcb, 0x5b
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
