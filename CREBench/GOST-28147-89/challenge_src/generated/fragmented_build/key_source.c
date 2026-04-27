/* instance_label=GOST-28147-89-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0xd2, 0x63, 0x43, 0xa6, 0xf7, 0x53, 0xf8, 0x51,
    0xef, 0xb4, 0xb0, 0xb2, 0x60, 0xff, 0x1a, 0xe8
};

static const uint8_t FRAG_ODD[] = {
    0x0e, 0xaf, 0xee, 0xf0, 0x4e, 0x83, 0xde, 0x2d,
    0x46, 0x61, 0xa6, 0xdd, 0x44, 0x4c, 0x68, 0x0e
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0xd5);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0xd5);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 32);
    }
}
