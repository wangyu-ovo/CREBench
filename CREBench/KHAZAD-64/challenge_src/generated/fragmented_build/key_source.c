/* instance_label=KHAZAD-64-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0xc5, 0xbd, 0x91, 0xdd, 0x19, 0x1d, 0xf7, 0x2c
};

static const uint8_t FRAG_ODD[] = {
    0xe7, 0x99, 0x88, 0x99, 0x19, 0x9c, 0x2f, 0x42
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0x95);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0x95);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 16);
    }
}
