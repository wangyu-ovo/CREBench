/* instance_label=CAST5-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0xb3, 0x01, 0xd4, 0x25, 0x2d, 0x71, 0xb6, 0x73
};

static const uint8_t FRAG_ODD[] = {
    0x0d, 0x24, 0x9e, 0x1e, 0xa2, 0x1f, 0x80, 0x28
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0xf3);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0xf3);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 16);
    }
}
