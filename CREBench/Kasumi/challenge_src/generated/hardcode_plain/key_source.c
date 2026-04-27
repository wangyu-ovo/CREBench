/* instance_label=Kasumi-hardcode_plain-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0xfb, 0x7c, 0xe3, 0x8c, 0x59, 0xb4, 0xc1, 0x73,
    0x87, 0x02, 0x1e, 0x4a, 0x29, 0x56, 0xc7, 0x3e
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
