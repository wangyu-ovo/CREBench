/* instance_label=DESX-weak_prng_seeded-random variant=lcg_seeded */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t CORR[] = {
    0x91, 0x1c, 0x81, 0x7a, 0x26, 0x41, 0xa0, 0xcc,
    0x1f, 0xcf, 0xb7, 0xd7, 0x2f, 0xc7, 0x77, 0x20,
    0xe0, 0xc4, 0xe4, 0xdb, 0x3c, 0x72, 0x0e, 0x3e
    };

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    volatile const uint8_t *corr = CORR;
    volatile uint32_t state = 0xe00a7c8aU ^ 0x57628150U;
    for (size_t i = 0; i < key_len; i++) {
        state = state * 1664525U + 1013904223U;
        volatile uint8_t prng = (uint8_t)((state >> ((i & 3U) * 8U)) & 0xFFU);
        key[i] = (uint8_t)(prng ^ corr[i % sizeof(CORR)]);
    }
}
