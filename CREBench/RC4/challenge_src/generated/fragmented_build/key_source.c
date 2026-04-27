/* instance_label=RC4-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0x2e, 0x3e, 0x61, 0x49, 0xa7, 0x1d, 0x21, 0x7f
};

static const uint8_t FRAG_ODD[] = {
    0x93, 0xad, 0x5b, 0x6a, 0x3d, 0x81, 0x58, 0xb3
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0x01);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0x01);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 16);
    }
}
