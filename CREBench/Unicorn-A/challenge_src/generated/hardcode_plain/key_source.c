/* instance_label=Unicorn-A-hardcode_plain-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x8c, 0x43, 0x63, 0x8c, 0x5f, 0x45, 0x62, 0x8a,
    0x23, 0x43, 0xe7, 0x80, 0x60, 0x01, 0x2a, 0xb9,
    0x3d, 0xeb, 0xad, 0xed, 0x22, 0xbc, 0xff, 0x1b,
    0x98, 0xa8, 0xb0, 0xfb, 0x68, 0x8a, 0x43, 0x6d
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
