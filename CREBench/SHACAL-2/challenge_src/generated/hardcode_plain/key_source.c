/* instance_label=SHACAL-2-hardcode_plain-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0xf5, 0x74, 0xe6, 0x44, 0xb8, 0x33, 0xb8, 0x45,
    0x54, 0xb1, 0x26, 0x3b, 0x7a, 0x7f, 0x4a, 0xe9,
    0x81, 0x7a, 0x7c, 0x6e, 0x5c, 0x18, 0x2b, 0x07,
    0xe7, 0x85, 0x45, 0x7e, 0x86, 0x03, 0x39, 0xfb
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
