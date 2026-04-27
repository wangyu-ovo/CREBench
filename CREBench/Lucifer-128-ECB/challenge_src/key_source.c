/* instance_label=Lucifer-128-ECB-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x3e, 0x02, 0x53, 0xc5, 0xee, 0xf2, 0xa4, 0x16,
    0xdb, 0xde, 0xfd, 0x69, 0xdb, 0x57, 0x8e, 0x9a
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
