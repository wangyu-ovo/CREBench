/* instance_label=CAST5-hardcode_plain-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x03, 0xba, 0x2c, 0x23, 0xd0, 0x6a, 0xcb, 0xbb,
    0x7d, 0x93, 0x63, 0x8e, 0xe0, 0x0c, 0xd0, 0x63
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
