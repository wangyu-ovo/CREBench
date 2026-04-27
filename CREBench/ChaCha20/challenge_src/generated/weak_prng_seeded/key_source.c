/* instance_label=ChaCha20-weak_prng_seeded-random variant=lcg_seeded */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t CORR[] = {
    0xc9, 0xcd, 0xf7, 0x8e, 0x90, 0x9b, 0x3b, 0xac,
    0x0b, 0xa2, 0xed, 0x1b, 0xda, 0xa6, 0xca, 0xf4,
    0xdd, 0xad, 0x6e, 0xd6, 0x0f, 0x42, 0xea, 0x9e,
    0xc8, 0x03, 0x99, 0xc2, 0xf0, 0x70, 0xbe, 0x02
    };

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    volatile const uint8_t *corr = CORR;
    volatile uint32_t state = 0x1c1e5794U ^ 0xf3abdd5aU;
    for (size_t i = 0; i < key_len; i++) {
        state = state * 1664525U + 1013904223U;
        volatile uint8_t prng = (uint8_t)((state >> ((i & 3U) * 8U)) & 0xFFU);
        key[i] = (uint8_t)(prng ^ corr[i % sizeof(CORR)]);
    }
}
