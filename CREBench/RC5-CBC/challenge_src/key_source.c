/* instance_label=RC5-CBC-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x39, 0xa5, 0x84, 0xba, 0x99, 0xc2, 0x7d, 0xbe,
    0x7a, 0x24, 0xf0, 0x65, 0x9c, 0xde, 0xe9, 0xfe
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
