/* instance_label=MARS-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0x76, 0x2d, 0x82, 0x1b, 0x63, 0x21, 0xec, 0xf7,
    0x34, 0xd3, 0x11, 0x44, 0xb9, 0xd4, 0x76, 0x61
};

static const uint8_t FRAG_ODD[] = {
    0x3f, 0x3f, 0xaf, 0xcc, 0x6b, 0x7c, 0xed, 0xd7,
    0x17, 0xfa, 0xe7, 0x0b, 0x12, 0x4c, 0xe4, 0x6d
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0x69);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0x69);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 32);
    }
}
