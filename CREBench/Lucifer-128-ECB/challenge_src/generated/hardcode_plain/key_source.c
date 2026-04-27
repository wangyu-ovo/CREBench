/* instance_label=Lucifer-128-ECB-hardcode_plain-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x98, 0x0b, 0xab, 0x3c, 0xab, 0x02, 0x1c, 0x96,
    0x89, 0x56, 0x97, 0x1a, 0x99, 0x24, 0x9b, 0x0b
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
