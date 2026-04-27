/* instance_label=Anubis-128-CBC-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0xcf, 0x92, 0x5e, 0x06, 0x9e, 0xef, 0xae, 0x7f,
    0xbf, 0x41, 0xe6, 0x09, 0x63, 0x17, 0x09, 0xd3
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
