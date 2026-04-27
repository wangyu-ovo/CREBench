/* instance_label=LOKI97-hardcode_plain-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x37, 0x32, 0x3c, 0xdc, 0x36, 0x47, 0x1c, 0x5f,
    0xa7, 0x72, 0x53, 0xbb, 0x14, 0x8e, 0xb5, 0x57,
    0x1a, 0x29, 0xcd, 0xcd, 0xf1, 0x52, 0x7b, 0x96,
    0x8a, 0x15, 0x16, 0x79, 0xf7, 0x6e, 0xec, 0x7e
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
