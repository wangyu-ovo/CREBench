/* instance_label=Kuznyechik-128-ECB-weak_prng_seeded-random variant=lcg_seeded */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t CORR[] = {
    0x6b, 0xdc, 0x88, 0x49, 0x71, 0x6e, 0xf0, 0x4c,
    0xac, 0x59, 0xd8, 0xd7, 0x52, 0x3f, 0xdd, 0x90,
    0x68, 0xad, 0x5b, 0x32, 0x00, 0xc7, 0x7c, 0x0d,
    0xda, 0x31, 0x4f, 0xbf, 0x59, 0x26, 0x58, 0xc1
    };

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    volatile const uint8_t *corr = CORR;
    volatile uint32_t state = 0xcb2b85beU ^ 0x1426e2bbU;
    for (size_t i = 0; i < key_len; i++) {
        state = state * 1664525U + 1013904223U;
        volatile uint8_t prng = (uint8_t)((state >> ((i & 3U) * 8U)) & 0xFFU);
        key[i] = (uint8_t)(prng ^ corr[i % sizeof(CORR)]);
    }
}
