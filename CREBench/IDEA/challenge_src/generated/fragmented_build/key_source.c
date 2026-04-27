/* instance_label=IDEA-fragmented_build-random variant=even_odd_xor */
#include <stddef.h>
#include <stdint.h>

#define INSECURE_KEY_NOOPT __attribute__((noinline, noclone, optimize("O0")))


static const uint8_t FRAG_EVEN[] = {
    0x77, 0x46, 0xbc, 0x82, 0x53, 0x76, 0xe5, 0x20
};

static const uint8_t FRAG_ODD[] = {
    0xd1, 0x64, 0x14, 0xbc, 0x7a, 0x9d, 0x43, 0x4b
};

INSECURE_KEY_NOOPT
static uint8_t rebuild_byte(size_t index) {
    volatile const uint8_t *even = FRAG_EVEN;
    volatile const uint8_t *odd = FRAG_ODD;
    volatile uint8_t value;
    if ((index & 1U) == 0U) {
        value = (uint8_t)(even[index / 2] ^ 0xd3);
    } else {
        value = (uint8_t)(odd[index / 2] ^ 0xd3);
    }
    return value;
}

INSECURE_KEY_NOOPT
void insecure_key_generate(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        key[i] = rebuild_byte(i % 16);
    }
}
