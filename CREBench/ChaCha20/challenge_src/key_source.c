/* instance_label=ChaCha20-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x30, 0x16, 0x62, 0x56, 0x2d, 0x4c, 0xb8, 0x85,
    0xd7, 0x44, 0x3d, 0xb9, 0xa4, 0x0c, 0x0a, 0xf8,
    0x4f, 0xfe, 0x90, 0x07, 0xb8, 0xc9, 0xd0, 0x54,
    0x61, 0x97, 0x37, 0xbb, 0x2e, 0xfb, 0x89, 0x81
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
