/* instance_label=SHACAL-2-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0x44, 0x74, 0x03, 0x82, 0x2b, 0xc5, 0xa4, 0x88,
    0x83, 0x05, 0xa3, 0xe6, 0xbc, 0x9e, 0xbd, 0x4e
};

static const uint8_t FRAG_ODD[] = {
    0x2c, 0x6b, 0x5a, 0x15, 0x30, 0x03, 0x43, 0x35,
    0xce, 0xf3, 0x7b, 0x74, 0xd5, 0xce, 0xd3, 0xe8
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0x5f);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0x5f);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 32);
    }
}
