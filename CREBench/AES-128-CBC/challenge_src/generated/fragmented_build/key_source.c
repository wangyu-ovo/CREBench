/* instance_label=AES-128-CBC-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0xc6, 0x99, 0x88, 0xa6, 0x17, 0xc2, 0xd8, 0xc2
};

static const uint8_t FRAG_ODD[] = {
    0x9a, 0xa6, 0xe6, 0x08, 0xad, 0xbb, 0x7b, 0x97
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
