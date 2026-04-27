/* instance_label=SC2000-hardcode_plain-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x88, 0xbb, 0xe4, 0x71, 0x55, 0x49, 0x39, 0x72,
    0x8d, 0xa1, 0x52, 0xc7, 0x36, 0xa4, 0x76, 0x4e,
    0x2b, 0x0a, 0x83, 0xf4, 0x64, 0x69, 0xb3, 0xc3,
    0xf7, 0xf4, 0xbf, 0xa9, 0x47, 0x38, 0xd6, 0x2f
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
