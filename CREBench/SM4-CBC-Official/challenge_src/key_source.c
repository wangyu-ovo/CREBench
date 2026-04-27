/* instance_label=SM4-CBC-Official-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x2d, 0x0d, 0x0a, 0xda, 0xf8, 0x83, 0x29, 0xad,
    0x7f, 0x00, 0x6c, 0x0b, 0xcd, 0xa7, 0x07, 0xc2
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
