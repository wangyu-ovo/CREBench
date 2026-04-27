/* instance_label=Kuznyechik-128-ECB-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0x38, 0x79, 0x53, 0x54, 0x50, 0xb1, 0xc7, 0x66,
    0x05, 0x9b, 0x73, 0x26, 0x1c, 0xde, 0x20, 0xbd
};

static const uint8_t FRAG_ODD[] = {
    0x9a, 0xc0, 0x66, 0x64, 0xc6, 0xde, 0x6e, 0x21,
    0xf6, 0x83, 0xa9, 0xa3, 0x7d, 0x07, 0x8d, 0x51
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0xf1);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0xf1);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 32);
    }
}
