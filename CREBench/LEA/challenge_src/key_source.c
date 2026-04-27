/* instance_label=LEA-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0xf7, 0x9a, 0x68, 0x4a, 0xea, 0xc2, 0x49, 0xb3,
    0xd9, 0xb3, 0x15, 0x69, 0x41, 0x99, 0x0a, 0xc9
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
