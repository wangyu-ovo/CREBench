#include "crypto1_stream.h"

#ifdef CONSTXOR_CRYPTO1_TABLES
#include "constxor_tables.h"
#endif

typedef struct {
    uint32_t odd;
    uint32_t even;
} crypto1_state;

static const uint32_t crypto1_feedback_masks[2] = {
    0x29CE5CU,
    0x870804U
};

static const uint32_t crypto1_filter_masks[5] = {
    0x0F22C0U,
    0x06C9C0U,
    0x03C8B0U,
    0x01E458U,
    0x00D938U
};

static const uint32_t crypto1_filter_output[1] = {
    0xEC57E80AU
};

static uint8_t bit32(uint32_t value, unsigned int bit) {
    return (uint8_t)((value >> bit) & 1U);
}

static uint8_t bit64(uint64_t value, unsigned int bit) {
    return (uint8_t)((value >> bit) & 1U);
}

static uint32_t load_be32(const uint8_t in[4]) {
    return ((uint32_t)in[0] << 24) |
           ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) |
           (uint32_t)in[3];
}

static uint64_t load_be48(const uint8_t in[CRYPTO1_KEY_BYTES]) {
    return ((uint64_t)in[0] << 40) |
           ((uint64_t)in[1] << 32) |
           ((uint64_t)in[2] << 24) |
           ((uint64_t)in[3] << 16) |
           ((uint64_t)in[4] << 8) |
           (uint64_t)in[5];
}

static const uint32_t *feedback_masks(void) {
#ifdef CONSTXOR_CRYPTO1_TABLES
    return constxor_crypto1_feedback_masks();
#else
    return crypto1_feedback_masks;
#endif
}

static const uint32_t *filter_masks(void) {
#ifdef CONSTXOR_CRYPTO1_TABLES
    return constxor_crypto1_filter_masks();
#else
    return crypto1_filter_masks;
#endif
}

static uint32_t filter_output_word(void) {
#ifdef CONSTXOR_CRYPTO1_TABLES
    return constxor_crypto1_filter_output()[0];
#else
    return crypto1_filter_output[0];
#endif
}

static uint8_t parity32(uint32_t x) {
    x ^= x >> 16;
    x ^= x >> 8;
    x ^= x >> 4;
    x &= 0x0FU;
    return bit32(0x6996U, x);
}

static uint8_t crypto1_filter(uint32_t x) {
    const uint32_t *m = filter_masks();
    uint32_t f = 0U;

    f  = (m[0] >> (x & 0x0FU)) & 16U;
    f |= (m[1] >> ((x >> 4) & 0x0FU)) & 8U;
    f |= (m[2] >> ((x >> 8) & 0x0FU)) & 4U;
    f |= (m[3] >> ((x >> 12) & 0x0FU)) & 2U;
    f |= (m[4] >> ((x >> 16) & 0x0FU)) & 1U;
    return bit32(filter_output_word(), f);
}

static void crypto1_init(crypto1_state *st, const uint8_t key[CRYPTO1_KEY_BYTES]) {
    uint64_t key48 = load_be48(key);
    st->odd = 0U;
    st->even = 0U;

    for (int i = 47; i > 0; i -= 2) {
        st->odd = (st->odd << 1) | bit64(key48, (unsigned int)((i - 1) ^ 7));
        st->even = (st->even << 1) | bit64(key48, (unsigned int)(i ^ 7));
    }
}

static uint8_t crypto1_bit(crypto1_state *st, uint8_t in, int is_encrypted) {
    const uint32_t *feedback = feedback_masks();
    uint8_t ret = crypto1_filter(st->odd);
    uint32_t feedin = 0U;
    uint32_t x;

    feedin  = (uint32_t)(ret & (is_encrypted ? 1 : 0));
    feedin ^= (uint32_t)(in ? 1 : 0);
    feedin ^= feedback[0] & st->odd;
    feedin ^= feedback[1] & st->even;
    st->even = (st->even << 1) | parity32(feedin);

    x = st->odd;
    st->odd = st->even;
    st->even = x;

    return ret;
}

static uint8_t crypto1_byte(crypto1_state *st, uint8_t in, int is_encrypted) {
    uint8_t ret = 0U;
    for (unsigned int i = 0; i < 8; ++i) {
        ret |= (uint8_t)(crypto1_bit(st, bit32(in, i), is_encrypted) << i);
    }
    return ret;
}

static void crypto1_auth_init(
    crypto1_state *st,
    const uint8_t key[CRYPTO1_KEY_BYTES],
    const uint8_t iv[CRYPTO1_IV_BYTES]
) {
    uint32_t uid = load_be32(iv);
    uint32_t nonce = load_be32(iv + 4);

    crypto1_init(st, key);
    for (size_t pos = 0; pos < 4; ++pos) {
        uint8_t uid_byte = (uint8_t)(uid >> (8U * (3U - pos)));
        uint8_t nonce_byte = iv[4 + pos];
        crypto1_byte(st, (uint8_t)(uid_byte ^ nonce_byte), 0);
    }
}

void crypto1_crypt(
    const uint8_t key[CRYPTO1_KEY_BYTES],
    const uint8_t iv[CRYPTO1_IV_BYTES],
    const uint8_t *input,
    uint8_t *output,
    size_t len
) {
    crypto1_state st;
    crypto1_auth_init(&st, key, iv);

    for (size_t i = 0; i < len; ++i) {
        output[i] = (uint8_t)(input[i] ^ crypto1_byte(&st, 0x00U, 0));
    }
}
