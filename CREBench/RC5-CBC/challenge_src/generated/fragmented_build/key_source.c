/* instance_label=RC5-CBC-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0x44, 0x2a, 0x11, 0xb3, 0x79, 0x3d, 0x04, 0x33
};

static const uint8_t FRAG_ODD[] = {
    0x33, 0xa6, 0x61, 0x48, 0x89, 0x1b, 0x90, 0xa1
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0x65);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0x65);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 16);
    }
}
