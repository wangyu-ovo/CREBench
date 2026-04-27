/* instance_label=Kalyna-128-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0x29, 0x8b, 0x21, 0x20, 0xc5, 0xca, 0x9f, 0x51
};

static const uint8_t FRAG_ODD[] = {
    0x5d, 0xc7, 0xe5, 0x1d, 0xc1, 0x11, 0x9a, 0xf8
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0x9b);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0x9b);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 16);
    }
}
