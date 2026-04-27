/* instance_label=Unicorn-A-weak_prng_seeded-random variant=lcg_seeded */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t CORR[] = {
    0x58, 0x92, 0x81, 0xff, 0x41, 0x60, 0x7d, 0x53,
    0x6e, 0x54, 0x1b, 0x99, 0x21, 0xea, 0x5a, 0x30,
    0x95, 0x67, 0x05, 0x78, 0xbb, 0xd8, 0x9f, 0x92,
    0x56, 0x9f, 0x3c, 0x3a, 0xa3, 0xd2, 0x20, 0x16
    };

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    volatile const uint8_t *corr = CORR;
    volatile uint32_t state = 0x3dd9064fU ^ 0xbafda4d1U;
    for (size_t i = 0; i < key_len; i++) {
        state = state * 1664525U + 1013904223U;
        volatile uint8_t prng = (uint8_t)((state >> ((i & 3U) * 8U)) & 0xFFU);
        key[i] = (uint8_t)(prng ^ corr[i % sizeof(CORR)]);
    }
}
