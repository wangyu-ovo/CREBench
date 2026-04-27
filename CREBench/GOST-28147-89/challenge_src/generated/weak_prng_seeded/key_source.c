/* instance_label=GOST-28147-89-weak_prng_seeded-random variant=lcg_seeded */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t CORR[] = {
    0x0f, 0xeb, 0xce, 0x8f, 0xd8, 0x86, 0x6e, 0x1b,
    0x1d, 0x80, 0x98, 0x1a, 0x3b, 0x61, 0x13, 0x20,
    0x27, 0x1e, 0x05, 0x36, 0x38, 0xf7, 0x0a, 0x19,
    0xb4, 0x39, 0x17, 0xbb, 0x49, 0x84, 0x69, 0x50
    };

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    volatile const uint8_t *corr = CORR;
    volatile uint32_t state = 0x230ff04bU ^ 0x6929108aU;
    for (size_t i = 0; i < key_len; i++) {
        state = state * 1664525U + 1013904223U;
        volatile uint8_t prng = (uint8_t)((state >> ((i & 3U) * 8U)) & 0xFFU);
        key[i] = (uint8_t)(prng ^ corr[i % sizeof(CORR)]);
    }
}
