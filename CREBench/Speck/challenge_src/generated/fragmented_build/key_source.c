/* instance_label=Speck-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0x7b, 0x15, 0xa1, 0x26, 0x93, 0xd4
};

static const uint8_t FRAG_ODD[] = {
    0xb7, 0xb9, 0xb0, 0x64, 0x16, 0x4a
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0x1f);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0x1f);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 12);
    }
}
