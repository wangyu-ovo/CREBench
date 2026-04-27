/* instance_label=NOEKEON-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0x51, 0x7d, 0x97, 0x90, 0x45, 0xfe, 0xf6, 0x60
};

static const uint8_t FRAG_ODD[] = {
    0x6e, 0xd6, 0x55, 0x31, 0x4f, 0xd7, 0x59, 0xda
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0x51);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0x51);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 16);
    }
}
