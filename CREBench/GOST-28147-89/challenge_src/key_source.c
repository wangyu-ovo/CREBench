/* instance_label=GOST-28147-89-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x25, 0x1b, 0x38, 0x44, 0x9c, 0x54, 0xaa, 0x23,
    0x6a, 0x69, 0x0b, 0x56, 0x61, 0x84, 0x41, 0x3c,
    0xc0, 0xf7, 0xd5, 0xa3, 0xed, 0x0d, 0x46, 0x2c,
    0x23, 0x0e, 0xa5, 0x17, 0xcd, 0x88, 0x3a, 0x22
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
