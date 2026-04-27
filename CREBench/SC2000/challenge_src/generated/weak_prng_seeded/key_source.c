/* instance_label=SC2000-weak_prng_seeded-random variant=lcg_seeded */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t CORR[] = {
    0x81, 0x44, 0x6d, 0x44, 0x8a, 0x52, 0x90, 0x92,
    0x2f, 0x5e, 0xfe, 0x36, 0xc1, 0xd7, 0x0c, 0xc6,
    0xf5, 0x8c, 0xeb, 0x0c, 0x48, 0xf7, 0x21, 0x66,
    0x6e, 0xd0, 0x81, 0x2f, 0x8c, 0xc1, 0xf4, 0xa1
    };

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    volatile const uint8_t *corr = CORR;
    volatile uint32_t state = 0x918076d3U ^ 0xfccefae6U;
    for (size_t i = 0; i < key_len; i++) {
        state = state * 1664525U + 1013904223U;
        volatile uint8_t prng = (uint8_t)((state >> ((i & 3U) * 8U)) & 0xFFU);
        key[i] = (uint8_t)(prng ^ corr[i % sizeof(CORR)]);
    }
}
