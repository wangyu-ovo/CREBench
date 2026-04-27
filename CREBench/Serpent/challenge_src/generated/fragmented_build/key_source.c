/* instance_label=Serpent-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0x61, 0x0b, 0x0b, 0xd8, 0x04, 0xd0, 0xed, 0x8e
};

static const uint8_t FRAG_ODD[] = {
    0x36, 0x48, 0x24, 0x14, 0x49, 0x9a, 0x2f, 0xc4
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0xed);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0xed);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 16);
    }
}
