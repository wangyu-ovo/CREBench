/* instance_label=E0-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x50, 0x4d, 0x75, 0xdb, 0x14, 0xa3, 0x52, 0x5f,
    0x4d, 0x1b, 0xe1, 0x7e, 0xd4, 0x79, 0xf5, 0x57
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
