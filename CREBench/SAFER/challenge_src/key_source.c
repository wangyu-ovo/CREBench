/* instance_label=SAFER-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0xb2, 0x8c, 0x54, 0xa3, 0xa7, 0x6e, 0x6e, 0x1f,
    0x0f, 0x80, 0x2d, 0x05, 0x56, 0x45, 0xf9, 0x11
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
