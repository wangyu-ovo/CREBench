/* instance_label=DESX-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x54, 0xc1, 0x3a, 0x42, 0xdc, 0x29, 0x3c, 0x91,
    0xa3, 0xa0, 0x59, 0xfb, 0x0c, 0xc3, 0x70, 0xdd,
    0x15, 0x32, 0x05, 0xa3, 0xb1, 0x70, 0xe8, 0x9f
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
