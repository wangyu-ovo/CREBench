/* instance_label=Serpent-baseline-random variant=raw_literal */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    static const uint8_t KEY_BYTES[] = {
    0xfd, 0x76, 0xff, 0x7e, 0x81, 0xa1, 0x36, 0x6f,
    0x38, 0xe4, 0x7f, 0x76, 0xfe, 0x90, 0x1a, 0x62
    };
    volatile const uint8_t *src = KEY_BYTES;

    for (size_t i = 0; i < key_len; i++) {
        key[i] = src[i % sizeof(KEY_BYTES)];
    }
}
