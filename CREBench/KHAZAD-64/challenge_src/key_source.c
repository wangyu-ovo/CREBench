/* instance_label=KHAZAD-64-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x44, 0x48, 0x87, 0xdb, 0x3e, 0xbc, 0x2e, 0xe3,
    0x17, 0x39, 0x6a, 0xce, 0x59, 0x25, 0xd2, 0x26
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
