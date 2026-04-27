/* instance_label=IDEA-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0xc7, 0x4e, 0x59, 0x83, 0xc0, 0x47, 0x23, 0x47,
    0xcd, 0xcf, 0x93, 0x9a, 0xd0, 0x6c, 0xc2, 0x8f
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
