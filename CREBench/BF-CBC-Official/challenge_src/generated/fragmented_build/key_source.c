/* instance_label=BF-CBC-Official-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0x8e, 0x72, 0x71, 0xc4, 0x5e, 0x1c, 0x7c, 0x5e
};

static const uint8_t FRAG_ODD[] = {
    0x82, 0x2b, 0x03, 0x9b, 0xa4, 0x0e, 0xbb, 0x21
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0xef);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0xef);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 16);
    }
}
