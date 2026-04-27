#include "a5_2.h"

#include <string.h>

#ifdef CONSTXOR_A52_TABLES
#include "constxor_tables.h"
#endif

#define A5_R1_LEN 19
#define A5_R2_LEN 22
#define A5_R3_LEN 23
#define A5_R4_LEN 17

static const uint32_t a52_register_masks[4] = {
    0x07ffffU,
    0x3fffffU,
    0x7fffffU,
    0x01ffffU
};

static const uint32_t a52_register_taps[4] = {
    0x072000U,
    0x300000U,
    0x700080U,
    0x010800U
};

static const uint32_t a52_r4_clock_bits[3] = {
    0x000400U,
    0x000008U,
    0x000080U
};

static const uint32_t a52_output_masks[9] = {
    0x08000U, 0x04000U, 0x01000U,
    0x10000U, 0x02000U, 0x00200U,
    0x40000U, 0x10000U, 0x02000U
};

static const uint8_t a52_output_polarity[9] = {
    0U, 1U, 0U,
    1U, 0U, 0U,
    0U, 0U, 1U
};

static const uint32_t *a52_masks(void) {
#ifdef CONSTXOR_A52_TABLES
    return constxor_a52_register_masks();
#else
    return a52_register_masks;
#endif
}

static const uint32_t *a52_taps(void) {
#ifdef CONSTXOR_A52_TABLES
    return constxor_a52_register_taps();
#else
    return a52_register_taps;
#endif
}

static const uint32_t *a52_clkbits(void) {
#ifdef CONSTXOR_A52_TABLES
    return constxor_a52_r4_clock_bits();
#else
    return a52_r4_clock_bits;
#endif
}

static const uint32_t *a52_out_masks(void) {
#ifdef CONSTXOR_A52_TABLES
    return constxor_a52_output_masks();
#else
    return a52_output_masks;
#endif
}

static const uint8_t *a52_out_polarity(void) {
#ifdef CONSTXOR_A52_TABLES
    return constxor_a52_output_polarity();
#else
    return a52_output_polarity;
#endif
}

static uint32_t a5_fn_count(uint32_t fn) {
    uint32_t t1 = fn / (26U * 51U);
    uint32_t t2 = fn % 26U;
    uint32_t t3 = fn % 51U;
    return (t1 << 11) | (t3 << 5) | t2;
}

static uint32_t parity32(uint32_t x) {
    x ^= x >> 16;
    x ^= x >> 8;
    x ^= x >> 4;
    x &= 0x0fU;
    return (0x6996U >> x) & 1U;
}

static uint32_t majority3(uint32_t v1, uint32_t v2, uint32_t v3) {
    return ((v1 != 0U) + (v2 != 0U) + (v3 != 0U)) >= 2;
}

static uint32_t clock_lfsr(uint32_t reg, uint32_t mask, uint32_t taps) {
    return ((reg << 1) & mask) | parity32(reg & taps);
}

static void a52_clock(uint32_t reg[4], int force) {
    const uint32_t *masks = a52_masks();
    const uint32_t *taps = a52_taps();
    const uint32_t *clk = a52_clkbits();
    uint32_t c0 = (reg[3] & clk[0]) != 0U;
    uint32_t c1 = (reg[3] & clk[1]) != 0U;
    uint32_t c2 = (reg[3] & clk[2]) != 0U;
    uint32_t maj = majority3(c0, c1, c2);

    if (force || maj == c0) {
        reg[0] = clock_lfsr(reg[0], masks[0], taps[0]);
    }
    if (force || maj == c1) {
        reg[1] = clock_lfsr(reg[1], masks[1], taps[1]);
    }
    if (force || maj == c2) {
        reg[2] = clock_lfsr(reg[2], masks[2], taps[2]);
    }
    reg[3] = clock_lfsr(reg[3], masks[3], taps[3]);
}

static uint8_t reg_mask_value(uint32_t reg, uint32_t mask, uint8_t invert) {
    uint8_t bit = (reg & mask) != 0U ? 1U : 0U;
    return invert ? (uint8_t)(bit ^ 1U) : bit;
}

static uint8_t a52_output(const uint32_t reg[4]) {
    const uint32_t *m = a52_out_masks();
    const uint8_t *p = a52_out_polarity();
    uint8_t b =
        (uint8_t)(
            ((reg[0] >> (A5_R1_LEN - 1)) ^
             (reg[1] >> (A5_R2_LEN - 1)) ^
             (reg[2] >> (A5_R3_LEN - 1))) & 1U
        );

    b ^= (uint8_t)majority3(
        reg_mask_value(reg[0], m[0], p[0]),
        reg_mask_value(reg[0], m[1], p[1]),
        reg_mask_value(reg[0], m[2], p[2])
    );
    b ^= (uint8_t)majority3(
        reg_mask_value(reg[1], m[3], p[3]),
        reg_mask_value(reg[1], m[4], p[4]),
        reg_mask_value(reg[1], m[5], p[5])
    );
    b ^= (uint8_t)majority3(
        reg_mask_value(reg[2], m[6], p[6]),
        reg_mask_value(reg[2], m[7], p[7]),
        reg_mask_value(reg[2], m[8], p[8])
    );

    return b & 1U;
}

static void pack_bits_msb(const uint8_t *bits, size_t bit_len, uint8_t *out) {
    memset(out, 0, (bit_len + 7U) / 8U);
    for (size_t i = 0; i < bit_len; ++i) {
        if (bits[i]) {
            out[i >> 3] |= (uint8_t)(1U << (7U - (i & 7U)));
        }
    }
}

void a5_2_generate_bursts(
    const uint8_t key[A5_2_KEY_BYTES],
    uint32_t frame_number,
    uint8_t dl_bits[A5_2_BURST_BITS],
    uint8_t ul_bits[A5_2_BURST_BITS]
) {
    uint32_t reg[4] = {0U, 0U, 0U, 0U};
    uint32_t fn_count = a5_fn_count(frame_number);

    for (int i = 0; i < 64; ++i) {
        uint32_t bit = (uint32_t)((key[7 - (i >> 3)] >> (i & 7)) & 1U);
        a52_clock(reg, 1);
        reg[0] ^= bit;
        reg[1] ^= bit;
        reg[2] ^= bit;
        reg[3] ^= bit;
    }

    for (int i = 0; i < 22; ++i) {
        uint32_t bit = (fn_count >> i) & 1U;
        a52_clock(reg, 1);
        reg[0] ^= bit;
        reg[1] ^= bit;
        reg[2] ^= bit;
        reg[3] ^= bit;
    }

    reg[0] |= 1U << 15;
    reg[1] |= 1U << 16;
    reg[2] |= 1U << 18;
    reg[3] |= 1U << 10;

    for (int i = 0; i < 99; ++i) {
        a52_clock(reg, 0);
    }

    for (int i = 0; i < A5_2_BURST_BITS; ++i) {
        a52_clock(reg, 0);
        dl_bits[i] = a52_output(reg);
    }

    for (int i = 0; i < A5_2_BURST_BITS; ++i) {
        a52_clock(reg, 0);
        ul_bits[i] = a52_output(reg);
    }
}

void a5_2_frame_stream(
    const uint8_t key[A5_2_KEY_BYTES],
    uint32_t frame_number,
    uint8_t stream[A5_2_FRAME_STREAM_BYTES]
) {
    uint8_t dl_bits[A5_2_BURST_BITS];
    uint8_t ul_bits[A5_2_BURST_BITS];
    a5_2_generate_bursts(key, frame_number, dl_bits, ul_bits);
    pack_bits_msb(dl_bits, A5_2_BURST_BITS, stream);
    pack_bits_msb(ul_bits, A5_2_BURST_BITS, stream + A5_2_BURST_BYTES);
}

void a5_2_crypt(
    const uint8_t key[A5_2_KEY_BYTES],
    uint32_t frame_number,
    const uint8_t *input,
    uint8_t *output,
    size_t len
) {
    uint8_t stream[A5_2_FRAME_STREAM_BYTES];
    size_t offset = 0;

    while (offset < len) {
        size_t chunk = len - offset;
        if (chunk > sizeof(stream)) {
            chunk = sizeof(stream);
        }

        a5_2_frame_stream(key, frame_number, stream);
        for (size_t i = 0; i < chunk; ++i) {
            output[offset + i] = (uint8_t)(input[offset + i] ^ stream[i]);
        }

        offset += chunk;
        frame_number++;
    }
}
