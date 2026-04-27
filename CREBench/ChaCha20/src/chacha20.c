#include "chacha20.h"

#include <string.h>

#ifdef CONSTXOR_CHACHA20_TABLES
#include "constxor_tables.h"
#endif

static const uint32_t chacha_sigma[4] = {
    0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U
};

static uint32_t load32_le(const uint8_t src[4]) {
    return ((uint32_t)src[0]) |
           ((uint32_t)src[1] << 8) |
           ((uint32_t)src[2] << 16) |
           ((uint32_t)src[3] << 24);
}

static void store32_le(uint8_t dst[4], uint32_t value) {
    dst[0] = (uint8_t)(value & 0xffU);
    dst[1] = (uint8_t)((value >> 8) & 0xffU);
    dst[2] = (uint8_t)((value >> 16) & 0xffU);
    dst[3] = (uint8_t)((value >> 24) & 0xffU);
}

static uint32_t rotl32(uint32_t value, unsigned int shift) {
    return (value << shift) | (value >> (32U - shift));
}

static void quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = rotl32(*d, 16);
    *c += *d; *b ^= *c; *b = rotl32(*b, 12);
    *a += *b; *d ^= *a; *d = rotl32(*d, 8);
    *c += *d; *b ^= *c; *b = rotl32(*b, 7);
}

static const uint32_t *sigma_words(void) {
#ifdef CONSTXOR_CHACHA20_TABLES
    return constxor_chacha_sigma();
#else
    return chacha_sigma;
#endif
}

static void chacha20_block(
    const uint8_t key[CHACHA20_KEY_BYTES],
    const uint8_t nonce[CHACHA20_NONCE_BYTES],
    uint32_t counter,
    uint8_t output[CHACHA20_BLOCK_BYTES]
) {
    uint32_t state[16];
    uint32_t working[16];
    const uint32_t *sigma = sigma_words();

    state[0] = sigma[0];
    state[1] = sigma[1];
    state[2] = sigma[2];
    state[3] = sigma[3];
    for (size_t i = 0; i < 8; ++i) {
        state[4 + i] = load32_le(key + (i * 4));
    }
    state[12] = counter;
    state[13] = load32_le(nonce);
    state[14] = load32_le(nonce + 4);
    state[15] = load32_le(nonce + 8);

    memcpy(working, state, sizeof(state));
    for (size_t round = 0; round < 10; ++round) {
        quarter_round(&working[0], &working[4], &working[8], &working[12]);
        quarter_round(&working[1], &working[5], &working[9], &working[13]);
        quarter_round(&working[2], &working[6], &working[10], &working[14]);
        quarter_round(&working[3], &working[7], &working[11], &working[15]);
        quarter_round(&working[0], &working[5], &working[10], &working[15]);
        quarter_round(&working[1], &working[6], &working[11], &working[12]);
        quarter_round(&working[2], &working[7], &working[8], &working[13]);
        quarter_round(&working[3], &working[4], &working[9], &working[14]);
    }

    for (size_t i = 0; i < 16; ++i) {
        store32_le(output + (i * 4), working[i] + state[i]);
    }
}

void chacha20_crypt(
    const uint8_t key[CHACHA20_KEY_BYTES],
    const uint8_t nonce[CHACHA20_NONCE_BYTES],
    uint32_t counter,
    const uint8_t *input,
    uint8_t *output,
    size_t len
) {
    uint8_t block[CHACHA20_BLOCK_BYTES];

    for (size_t offset = 0; offset < len; offset += CHACHA20_BLOCK_BYTES) {
        size_t take = len - offset;
        if (take > CHACHA20_BLOCK_BYTES) {
            take = CHACHA20_BLOCK_BYTES;
        }

        chacha20_block(key, nonce, counter, block);
        for (size_t i = 0; i < take; ++i) {
            output[offset + i] = (uint8_t)(input[offset + i] ^ block[i]);
        }
        counter++;
    }
}

