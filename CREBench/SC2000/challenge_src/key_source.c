/* instance_label=SC2000-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x42, 0xc1, 0x5e, 0x2b, 0xd9, 0x8c, 0xa9, 0x17,
    0x36, 0x93, 0x42, 0x2a, 0xc4, 0x78, 0xc4, 0x2a,
    0x90, 0xae, 0x7b, 0x6c, 0xa1, 0x9a, 0x14, 0x50,
    0x00, 0x8f, 0xf9, 0x10, 0xe3, 0x3b, 0x6a, 0x97
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
