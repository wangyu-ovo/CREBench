/* instance_label=MISTY1-64-hardcode_plain-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x6f, 0x29, 0xcc, 0x66, 0x2a, 0x47, 0xc6, 0x28,
    0x1d, 0xd4, 0x9c, 0xa7, 0x2e, 0x6b, 0xa0, 0x65
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
