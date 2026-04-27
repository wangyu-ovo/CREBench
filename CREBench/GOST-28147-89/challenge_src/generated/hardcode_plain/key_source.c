/* instance_label=GOST-28147-89-hardcode_plain-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0xd9, 0x5d, 0x04, 0x82, 0xe5, 0x8d, 0x87, 0xca,
    0x67, 0x01, 0x98, 0x04, 0xf3, 0x5f, 0x60, 0xb0,
    0xe1, 0x5c, 0xbf, 0x08, 0x7b, 0x92, 0xce, 0xd1,
    0x23, 0x98, 0x8c, 0x06, 0x1b, 0x8d, 0xcd, 0x91
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
