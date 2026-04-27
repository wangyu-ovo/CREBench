/* instance_label=XTEA-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0x17, 0x5d, 0x5d, 0x5a, 0x76, 0x23, 0x41, 0xf4
};

static const uint8_t FRAG_ODD[] = {
    0xb1, 0x04, 0xb5, 0x74, 0x54, 0x32, 0xba, 0xf0
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0xfb);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0xfb);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 16);
    }
}
