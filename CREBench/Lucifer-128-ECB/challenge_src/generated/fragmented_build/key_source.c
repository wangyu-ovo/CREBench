/* instance_label=Lucifer-128-ECB-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0x87, 0xc7, 0xca, 0xe5, 0xc6, 0x01, 0x97, 0x33
};

static const uint8_t FRAG_ODD[] = {
    0xe2, 0x5b, 0xb1, 0xc6, 0xe0, 0xc7, 0x06, 0xf2
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0xd9);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0xd9);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 16);
    }
}
