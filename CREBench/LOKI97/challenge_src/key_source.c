/* instance_label=LOKI97-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x7c, 0x40, 0x58, 0x2c, 0x3b, 0x91, 0xce, 0xf5,
    0x2b, 0x42, 0xa6, 0xb5, 0xce, 0x92, 0xe0, 0x37,
    0x10, 0x63, 0xb3, 0x27, 0x6a, 0xd8, 0x99, 0xf5,
    0xe2, 0xba, 0xfa, 0xb4, 0xea, 0x4b, 0x32, 0x9c
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
