/* instance_label=SHARK-hardcode_plain-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x62, 0xc4, 0xaf, 0xe3, 0xc2, 0x16, 0x53, 0xc9,
    0x4a, 0x0b, 0x31, 0x24, 0x92, 0x16, 0xc0, 0x2a
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
