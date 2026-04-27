/* instance_label=MISTY1-64-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0x95, 0x05, 0x15, 0x33, 0x0c, 0x71, 0x57, 0x1c
};

static const uint8_t FRAG_ODD[] = {
    0xdb, 0x88, 0xd1, 0x5f, 0xa0, 0x32, 0x20, 0x53
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0x45);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0x45);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 16);
    }
}
