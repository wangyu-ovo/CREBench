/* instance_label=SC2000-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0xda, 0x7e, 0x88, 0xc7, 0xe4, 0x37, 0xdc, 0x3e,
    0x76, 0x92, 0x89, 0x31, 0x46, 0xe5, 0x42, 0x2d
};

static const uint8_t FRAG_ODD[] = {
    0x66, 0xf9, 0x86, 0xee, 0xfa, 0x44, 0x16, 0x5e,
    0x41, 0xec, 0xb7, 0x37, 0x00, 0x53, 0xfd, 0x57
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0x25);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0x25);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 32);
    }
}
