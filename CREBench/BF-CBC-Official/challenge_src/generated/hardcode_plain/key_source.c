/* instance_label=BF-CBC-Official-hardcode_plain-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0xf3, 0xe4, 0xca, 0xd2, 0x83, 0xc9, 0x35, 0x28,
    0xf2, 0xfb, 0xcc, 0x92, 0xf5, 0x75, 0x07, 0x92
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
