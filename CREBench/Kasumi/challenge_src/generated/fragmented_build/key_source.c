/* instance_label=Kasumi-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0xad, 0x8a, 0xf4, 0x0f, 0xfe, 0xf8, 0x00, 0x67
};

static const uint8_t FRAG_ODD[] = {
    0x61, 0xcc, 0x71, 0x26, 0x31, 0x89, 0x8f, 0xbe
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0xaf);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0xaf);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 16);
    }
}
