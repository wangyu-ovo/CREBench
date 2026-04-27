/* instance_label=Serpent-hardcode_plain-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0xca, 0x45, 0x13, 0xc7, 0xee, 0x61, 0x0f, 0xb8,
    0xcc, 0xcf, 0xf3, 0x89, 0x70, 0x17, 0x68, 0xad
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
