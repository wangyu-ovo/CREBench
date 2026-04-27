/* instance_label=Kasumi-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x77, 0xf2, 0xb5, 0x42, 0x12, 0x17, 0xb5, 0x8e,
    0xfa, 0xf3, 0x11, 0x09, 0xd0, 0x05, 0x46, 0x8d
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
