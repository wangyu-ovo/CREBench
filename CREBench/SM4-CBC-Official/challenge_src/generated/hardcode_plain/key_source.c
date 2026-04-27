/* instance_label=SM4-CBC-Official-hardcode_plain-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0xf6, 0xea, 0x45, 0xcd, 0xda, 0x56, 0x81, 0xe0,
    0x85, 0x01, 0xaa, 0x47, 0x81, 0x92, 0x19, 0xb8
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
