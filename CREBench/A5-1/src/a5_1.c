#include "a5_1.h"

#include <string.h>

#ifdef CONSTXOR_A51_TABLES
#include "constxor_tables.h"
#endif

#define A5_R1_LEN 19
#define A5_R2_LEN 22
#define A5_R3_LEN 23

static const uint32_t a51_register_masks[3] = {
    0x07ffffU,
    0x3fffffU,
    0x7fffffU
};

static const uint32_t a51_register_taps[3] = {
    0x072000U,
    0x300000U,
    0x700080U
};

static const uint32_t a51_clock_bits[3] = {
    0x000100U,
    0x000400U,
    0x000400U
};

static const uint32_t *a51_masks(void) {
#ifdef CONSTXOR_A51_TABLES
    return constxor_a51_register_masks();
#else
    return a51_register_masks;
#endif
}

static const uint32_t *a51_taps(void) {
#ifdef CONSTXOR_A51_TABLES
    return constxor_a51_register_taps();
#else
    return a51_register_taps;
#endif
}

static const uint32_t *a51_clkbits(void) {
#ifdef CONSTXOR_A51_TABLES
    return constxor_a51_clock_bits();
#else
    return a51_clock_bits;
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

static void a51_clock(uint32_t reg[3], int force) {
    const uint32_t *masks = a51_masks();
    const uint32_t *taps = a51_taps();
    const uint32_t *clk = a51_clkbits();
    uint32_t c0 = (reg[0] & clk[0]) != 0U;
    uint32_t c1 = (reg[1] & clk[1]) != 0U;
    uint32_t c2 = (reg[2] & clk[2]) != 0U;
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
}

static uint8_t a51_output(const uint32_t reg[3]) {
    return (uint8_t)(
        (reg[0] >> (A5_R1_LEN - 1)) ^
        (reg[1] >> (A5_R2_LEN - 1)) ^
        (reg[2] >> (A5_R3_LEN - 1))
    );
}

static void pack_bits_msb(const uint8_t *bits, size_t bit_len, uint8_t *out) {
    memset(out, 0, (bit_len + 7U) / 8U);
    for (size_t i = 0; i < bit_len; ++i) {
        if (bits[i]) {
            out[i >> 3] |= (uint8_t)(1U << (7U - (i & 7U)));
        }
    }
}

void a5_1_generate_bursts(
    const uint8_t key[A5_1_KEY_BYTES],
    uint32_t frame_number,
    uint8_t dl_bits[A5_1_BURST_BITS],
    uint8_t ul_bits[A5_1_BURST_BITS]
) {
    uint32_t reg[3] = {0U, 0U, 0U};
    uint32_t fn_count = a5_fn_count(frame_number);

    for (int i = 0; i < 64; ++i) {
        uint32_t bit = (uint32_t)((key[7 - (i >> 3)] >> (i & 7)) & 1U);
        a51_clock(reg, 1);
        reg[0] ^= bit;
        reg[1] ^= bit;
        reg[2] ^= bit;
    }

    for (int i = 0; i < 22; ++i) {
        uint32_t bit = (fn_count >> i) & 1U;
        a51_clock(reg, 1);
        reg[0] ^= bit;
        reg[1] ^= bit;
        reg[2] ^= bit;
    }

    for (int i = 0; i < 100; ++i) {
        a51_clock(reg, 0);
    }

    for (int i = 0; i < A5_1_BURST_BITS; ++i) {
        a51_clock(reg, 0);
        dl_bits[i] = a51_output(reg);
    }

    for (int i = 0; i < A5_1_BURST_BITS; ++i) {
        a51_clock(reg, 0);
        ul_bits[i] = a51_output(reg);
    }
}

void a5_1_frame_stream(
    const uint8_t key[A5_1_KEY_BYTES],
    uint32_t frame_number,
    uint8_t stream[A5_1_FRAME_STREAM_BYTES]
) {
    uint8_t dl_bits[A5_1_BURST_BITS];
    uint8_t ul_bits[A5_1_BURST_BITS];
    a5_1_generate_bursts(key, frame_number, dl_bits, ul_bits);
    pack_bits_msb(dl_bits, A5_1_BURST_BITS, stream);
    pack_bits_msb(ul_bits, A5_1_BURST_BITS, stream + A5_1_BURST_BYTES);
}

void a5_1_crypt(
    const uint8_t key[A5_1_KEY_BYTES],
    uint32_t frame_number,
    const uint8_t *input,
    uint8_t *output,
    size_t len
) {
    uint8_t stream[A5_1_FRAME_STREAM_BYTES];
    size_t offset = 0;

    while (offset < len) {
        size_t chunk = len - offset;
        if (chunk > sizeof(stream)) {
            chunk = sizeof(stream);
        }

        a5_1_frame_stream(key, frame_number, stream);
        for (size_t i = 0; i < chunk; ++i) {
            output[offset + i] = (uint8_t)(input[offset + i] ^ stream[i]);
        }

        offset += chunk;
        frame_number++;
    }
}
