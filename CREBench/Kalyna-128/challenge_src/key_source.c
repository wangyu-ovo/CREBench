/* instance_label=Kalyna-128-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x0f, 0x81, 0x3c, 0xc5, 0x12, 0x73, 0x46, 0x79,
    0xe3, 0x28, 0x21, 0x26, 0xfd, 0x0c, 0x97, 0x8a
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
