/* instance_label=MISTY1-64-weak_prng_seeded-random variant=lcg_seeded */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t CORR[] = {
    0x14, 0x64, 0x0e, 0x92, 0xc2, 0x69, 0xd2, 0xfa,
    0x59, 0x7b, 0x69, 0x60, 0xca, 0xd5, 0x32, 0xa1
    };

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    volatile const uint8_t *corr = CORR;
    volatile uint32_t state = 0xb64a67c1U ^ 0xfb656c4eU;
    for (size_t i = 0; i < key_len; i++) {
        state = state * 1664525U + 1013904223U;
        volatile uint8_t prng = (uint8_t)((state >> ((i & 3U) * 8U)) & 0xFFU);
        key[i] = (uint8_t)(prng ^ corr[i % sizeof(CORR)]);
    }
}
