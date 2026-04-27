/* instance_label=Anubis-128-CBC-hardcode_plain-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0xa5, 0x67, 0x5f, 0xc6, 0x41, 0xdc, 0xfa, 0xfd,
    0xa8, 0x14, 0x70, 0x50, 0x2e, 0xe8, 0x0d, 0x05
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
