/* instance_label=SHARK-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x0f, 0x51, 0xc8, 0x0a, 0xce, 0x1c, 0xb1, 0xd6,
    0xf4, 0x1c, 0xaa, 0x61, 0xe9, 0x26, 0xc3, 0x74
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
