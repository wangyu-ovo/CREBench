/* instance_label=LOKI97-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0x01, 0x0a, 0xc9, 0xa1, 0x0b, 0x6f, 0xe1, 0xab,
    0xa3, 0x00, 0xc8, 0xc5, 0x75, 0x52, 0x4f, 0x04
};

static const uint8_t FRAG_ODD[] = {
    0xec, 0x10, 0x90, 0xe9, 0x21, 0x81, 0x7e, 0x70,
    0x2b, 0x76, 0x1d, 0xf2, 0x2f, 0xc9, 0xe2, 0xad
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0x7f);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0x7f);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 32);
    }
}
