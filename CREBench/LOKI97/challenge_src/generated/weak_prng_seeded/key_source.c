/* instance_label=LOKI97-weak_prng_seeded-random variant=lcg_seeded */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t CORR[] = {
    0x2c, 0x97, 0x7d, 0x11, 0xf8, 0x4d, 0x5d, 0x26,
    0xed, 0xab, 0xf9, 0x68, 0xd9, 0xff, 0x8c, 0x07,
    0x80, 0xb8, 0x73, 0x3a, 0x13, 0x41, 0xd0, 0xe2,
    0xf8, 0xa8, 0x64, 0xe4, 0xfe, 0xd5, 0xf5, 0x73
    };

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    volatile const uint8_t *corr = CORR;
    volatile uint32_t state = 0x17794021U ^ 0x59a04b6dU;
    for (size_t i = 0; i < key_len; i++) {
        state = state * 1664525U + 1013904223U;
        volatile uint8_t prng = (uint8_t)((state >> ((i & 3U) * 8U)) & 0xFFU);
        key[i] = (uint8_t)(prng ^ corr[i % sizeof(CORR)]);
    }
}
