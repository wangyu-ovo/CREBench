/* instance_label=LEA-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0x4d, 0x20, 0x4b, 0x01, 0x40, 0xbe, 0x2d, 0x7f
};

static const uint8_t FRAG_ODD[] = {
    0x5c, 0x2d, 0xb3, 0x1c, 0xd2, 0x5a, 0xe7, 0xd8
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0xf7);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0xf7);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 16);
    }
}
