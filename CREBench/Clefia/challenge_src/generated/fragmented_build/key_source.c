/* instance_label=Clefia-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0xbc, 0x4e, 0x4e, 0xc6, 0x11, 0xc9, 0x00, 0xe2
};

static const uint8_t FRAG_ODD[] = {
    0x22, 0xeb, 0x52, 0xd9, 0x9c, 0x03, 0x25, 0x71
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0xcf);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0xcf);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 16);
    }
}
