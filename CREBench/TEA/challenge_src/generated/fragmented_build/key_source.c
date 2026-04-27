/* instance_label=TEA-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0x48, 0x04, 0x20, 0x35, 0xc7, 0x34, 0x2b, 0x77
};

static const uint8_t FRAG_ODD[] = {
    0x4d, 0xad, 0xee, 0xdc, 0x9c, 0xc2, 0x0b, 0xb5
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0xe3);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0xe3);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 16);
    }
}
