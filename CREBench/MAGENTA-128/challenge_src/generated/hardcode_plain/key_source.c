/* instance_label=MAGENTA-128-hardcode_plain-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x38, 0x5b, 0x64, 0x9c, 0x4b, 0xfb, 0x9a, 0x40,
    0xfc, 0xaa, 0x33, 0x4d, 0xd1, 0x1b, 0x06, 0x9e
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
