/* instance_label=MARS-weak_prng_seeded-random variant=lcg_seeded */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t CORR[] = {
    0x4d, 0x1d, 0xdf, 0xe0, 0xfa, 0x4b, 0xda, 0xb6,
    0x6c, 0x35, 0x92, 0x50, 0xa5, 0x21, 0x39, 0x86,
    0x0d, 0x5e, 0xcf, 0x7d, 0x33, 0x46, 0x29, 0x01,
    0x54, 0x09, 0xcd, 0x9c, 0xa3, 0xcd, 0xdc, 0x8e
    };

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    volatile const uint8_t *corr = CORR;
    volatile uint32_t state = 0xf2329f99U ^ 0xd14a3d79U;
    for (size_t i = 0; i < key_len; i++) {
        state = state * 1664525U + 1013904223U;
        volatile uint8_t prng = (uint8_t)((state >> ((i & 3U) * 8U)) & 0xFFU);
        key[i] = (uint8_t)(prng ^ corr[i % sizeof(CORR)]);
    }
}
