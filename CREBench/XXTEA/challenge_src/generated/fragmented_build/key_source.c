/* instance_label=XXTEA-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0x5d, 0x5a, 0xb8, 0x73, 0xd0, 0x9d, 0x72, 0x4e
};

static const uint8_t FRAG_ODD[] = {
    0x3b, 0x33, 0xc3, 0x3a, 0x86, 0x2f, 0x67, 0x88
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0x7d);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0x7d);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 16);
    }
}
