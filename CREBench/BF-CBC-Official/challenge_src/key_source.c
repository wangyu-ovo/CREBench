/* instance_label=BF-CBC-Official-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x29, 0x4f, 0x42, 0x50, 0x67, 0xd1, 0x4f, 0xf0,
    0x4b, 0x46, 0x8c, 0x07, 0x75, 0x00, 0x6f, 0xdb
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
