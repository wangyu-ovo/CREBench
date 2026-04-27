/* instance_label=Kuznyechik-128-ECB-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0xc6, 0xc8, 0x09, 0x86, 0x04, 0x0e, 0x8f, 0x78,
    0xe4, 0x67, 0xa4, 0x95, 0x61, 0x16, 0x98, 0x27,
    0xa1, 0xcb, 0xd5, 0x7d, 0x08, 0x99, 0x8e, 0xbe,
    0xfa, 0xaa, 0x37, 0xac, 0x15, 0x8e, 0x49, 0x21
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
