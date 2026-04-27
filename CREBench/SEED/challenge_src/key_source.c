/* instance_label=SEED-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x6f, 0x41, 0xf4, 0xca, 0x0c, 0xdf, 0x79, 0xc4,
    0x4d, 0xe0, 0x4e, 0x35, 0x30, 0xa5, 0x72, 0xe3
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
