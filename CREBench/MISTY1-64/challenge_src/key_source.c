/* instance_label=MISTY1-64-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x4b, 0x97, 0xf5, 0x8f, 0x4e, 0x99, 0x52, 0x37,
    0x7b, 0x1a, 0x9a, 0x54, 0xe6, 0x78, 0x11, 0x6a
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
