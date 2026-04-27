/* instance_label=SM4-CBC-Official-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0x1f, 0xf1, 0xba, 0x9b, 0x55, 0xc0, 0x0d, 0xf6
};

static const uint8_t FRAG_ODD[] = {
    0xf5, 0x52, 0x11, 0x48, 0x53, 0x6a, 0xa0, 0x8b
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0x5d);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0x5d);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 16);
    }
}
