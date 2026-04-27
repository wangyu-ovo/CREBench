/* instance_label=ChaCha20-hardcode_plain-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0xe0, 0xa4, 0xc0, 0x6b, 0x53, 0x6b, 0xd3, 0x04,
    0x4c, 0x6d, 0x98, 0xd1, 0x1c, 0xde, 0xfe, 0x26,
    0xd4, 0xdf, 0x45, 0xfd, 0xdc, 0xb7, 0xab, 0x32,
    0xbb, 0x56, 0x39, 0x05, 0xe9, 0xd1, 0x60, 0x50
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
