/* instance_label=Kalyna-128-hardcode_plain-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x7a, 0xd0, 0x3d, 0x0f, 0x15, 0x9b, 0xab, 0x13,
    0x9b, 0x8e, 0x20, 0xca, 0x5b, 0xa8, 0xfb, 0x81
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
