/* instance_label=XTEA-hardcode_plain-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x15, 0xea, 0xa7, 0x8a, 0xfd, 0xc4, 0x41, 0xa8,
    0xa8, 0xb1, 0x74, 0x88, 0x03, 0x4c, 0x22, 0xa1
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
