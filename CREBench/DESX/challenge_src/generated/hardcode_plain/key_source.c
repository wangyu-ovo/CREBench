/* instance_label=DESX-hardcode_plain-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x53, 0xbd, 0x30, 0x84, 0xa9, 0x5e, 0x4f, 0xbc,
    0x44, 0x99, 0x98, 0xf7, 0xab, 0x76, 0x35, 0x0d,
    0xd2, 0x3e, 0x83, 0x37, 0xb5, 0x45, 0x2a, 0x05
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
