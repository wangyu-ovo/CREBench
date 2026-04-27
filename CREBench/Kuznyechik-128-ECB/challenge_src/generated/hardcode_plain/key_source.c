/* instance_label=Kuznyechik-128-ECB-hardcode_plain-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x9a, 0xd1, 0x77, 0x18, 0xca, 0xea, 0x05, 0x3b,
    0x2d, 0x80, 0x6a, 0x1e, 0xb5, 0xac, 0x69, 0xfd,
    0xf1, 0xaa, 0x64, 0x31, 0xb7, 0x56, 0x70, 0x88,
    0x9d, 0xaa, 0xf5, 0x95, 0x09, 0x6a, 0x46, 0x87
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
