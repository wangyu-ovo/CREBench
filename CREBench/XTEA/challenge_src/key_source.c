/* instance_label=XTEA-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x1b, 0xdb, 0x43, 0x38, 0x0d, 0x9c, 0xa0, 0x4c,
    0x1a, 0xbd, 0xee, 0x26, 0xd0, 0x19, 0x94, 0xe3
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
