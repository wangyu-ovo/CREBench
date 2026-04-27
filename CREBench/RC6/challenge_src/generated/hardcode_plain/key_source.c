/* instance_label=RC6-hardcode_plain-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0x81, 0x4a, 0x7e, 0x25, 0x52, 0xc1, 0xc0, 0xdb,
    0x9d, 0xd4, 0x7b, 0x16, 0xab, 0xa6, 0x0e, 0x4e
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
