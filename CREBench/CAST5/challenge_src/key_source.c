/* instance_label=CAST5-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0xb8, 0xbd, 0xe1, 0x68, 0x0b, 0xff, 0x42, 0xff,
    0xf4, 0xd0, 0xc3, 0xd7, 0xec, 0x12, 0x3b, 0xf9
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
