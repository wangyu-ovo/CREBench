/* instance_label=RC6-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x25, 0x0d, 0x7a, 0xca, 0x7c, 0xde, 0xd8, 0x7c,
    0x45, 0xaf, 0xae, 0x40, 0x98, 0xfd, 0x44, 0x19
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
