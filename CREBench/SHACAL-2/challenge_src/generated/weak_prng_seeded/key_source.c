/* instance_label=SHACAL-2-weak_prng_seeded-random variant=lcg_seeded */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t CORR[] = {
    0x0e, 0xd5, 0x06, 0x02, 0x8b, 0x6f, 0x45, 0xbf,
    0x49, 0xd8, 0xd4, 0x2d, 0xc4, 0x24, 0x61, 0xa6,
    0x71, 0x6d, 0x06, 0x6d, 0x61, 0x64, 0x81, 0x46,
    0x5b, 0xff, 0x8d, 0x5d, 0x15, 0xa5, 0x1d, 0x46
    };

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    volatile const uint8_t *corr = CORR;
    volatile uint32_t state = 0x2ca7284dU ^ 0xf07fcb42U;
    for (size_t i = 0; i < key_len; i++) {
        state = state * 1664525U + 1013904223U;
        volatile uint8_t prng = (uint8_t)((state >> ((i & 3U) * 8U)) & 0xFFU);
        key[i] = (uint8_t)(prng ^ corr[i % sizeof(CORR)]);
    }
}
