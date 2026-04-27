/* instance_label=Anubis-128-CBC-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0xd5, 0xa2, 0x5d, 0x1b, 0x4c, 0x9d, 0x63, 0xb1
};

static const uint8_t FRAG_ODD[] = {
    0x2b, 0x3a, 0x14, 0x29, 0xb7, 0x84, 0x7d, 0x70
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0x5b);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0x5b);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 16);
    }
}
