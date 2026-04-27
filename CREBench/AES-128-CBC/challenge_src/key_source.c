/* instance_label=AES-128-CBC-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x22, 0xa6, 0x9f, 0x1a, 0xc9, 0x90, 0x18, 0x4f,
    0x78, 0x72, 0xb9, 0x82, 0x79, 0xd9, 0x92, 0x8e
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
