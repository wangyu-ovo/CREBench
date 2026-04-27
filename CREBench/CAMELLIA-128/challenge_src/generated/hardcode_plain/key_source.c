/* instance_label=CAMELLIA-128-hardcode_plain-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0xf5, 0x1a, 0xac, 0xeb, 0xd5, 0x77, 0x0b, 0x97,
    0xaa, 0x68, 0xd7, 0x26, 0x2c, 0xdc, 0x5a, 0x7b
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
