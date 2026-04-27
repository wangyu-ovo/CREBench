/* instance_label=MAGENTA-128-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0xf8, 0x5f, 0x2e, 0xc6, 0x1a, 0xb4, 0x51, 0x54,
    0xed, 0x5a, 0xed, 0xaf, 0x1b, 0xbe, 0xb3, 0x04
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
