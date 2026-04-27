/* instance_label=SHACAL-2-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x73, 0xed, 0x7c, 0x11, 0x10, 0x4a, 0x05, 0xcd,
    0xcd, 0x36, 0x3c, 0x7b, 0x6f, 0xa5, 0xab, 0x65,
    0x2d, 0x16, 0x09, 0xcd, 0xd5, 0x22, 0xbd, 0x2d,
    0x3e, 0x38, 0x9d, 0x5d, 0x3a, 0x90, 0x9a, 0x88
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
