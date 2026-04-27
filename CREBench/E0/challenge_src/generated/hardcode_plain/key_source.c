/* instance_label=E0-hardcode_plain-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x8d, 0x17, 0x8b, 0x0a, 0xae, 0xf3, 0xe6, 0xcb,
    0x8c, 0x6b, 0x7c, 0xd1, 0x07, 0x67, 0x2f, 0x1a
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
