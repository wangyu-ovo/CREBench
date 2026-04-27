/* instance_label=MARS-hardcode_plain-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x34, 0x29, 0xc5, 0x3b, 0x47, 0xa2, 0xa2, 0x55,
    0x7a, 0xc4, 0xf5, 0xa9, 0x43, 0xf9, 0x1b, 0xf6,
    0x29, 0x05, 0x93, 0xe7, 0x25, 0x68, 0x05, 0xec,
    0x88, 0x64, 0xef, 0xed, 0xcc, 0x3c, 0x04, 0x7f
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
