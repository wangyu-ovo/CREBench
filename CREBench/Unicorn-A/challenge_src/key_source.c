/* instance_label=Unicorn-A-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x18, 0xe5, 0xf3, 0x27, 0xd7, 0x2b, 0xc4, 0x3f,
    0x0b, 0xef, 0x28, 0x89, 0xdd, 0xcb, 0x0e, 0x93,
    0x82, 0xcf, 0x3f, 0x60, 0x88, 0x83, 0x09, 0x1d,
    0xcd, 0x43, 0x40, 0x2d, 0xed, 0x6f, 0x0b, 0xff
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
