/* instance_label=Unicorn-A-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0xbc, 0xae, 0x78, 0xea, 0x42, 0x62, 0x29, 0xdc,
    0x7e, 0x5e, 0x68, 0x5e, 0x18, 0x42, 0xd9, 0x59
};

static const uint8_t FRAG_ODD[] = {
    0x61, 0xc6, 0x9e, 0x07, 0x41, 0x46, 0xfe, 0x79,
    0x5c, 0xf5, 0x8a, 0xc7, 0x43, 0xa4, 0x54, 0x55
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0xc5);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0xc5);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 32);
    }
}
