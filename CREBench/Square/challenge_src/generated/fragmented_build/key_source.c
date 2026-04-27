/* instance_label=Square-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0xe5, 0x23, 0xf4, 0x2a, 0xa9, 0xb0, 0x9d, 0x10
};

static const uint8_t FRAG_ODD[] = {
    0x45, 0x1a, 0xfb, 0xd7, 0xd9, 0x84, 0xfa, 0x2b
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
