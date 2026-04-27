#include "e0.h"

#include <string.h>

#ifdef CONSTXOR_E0_TABLES
#include "constxor_tables.h"
#endif

typedef struct {
    uint64_t value;
    uint8_t size;
} e0_register;

typedef struct {
    e0_register regs[4];
    uint8_t state;
    uint8_t reg_output;
    uint8_t key_bit;
} e0_state;

static const uint8_t e0_register_sizes[4] = {
    25, 31, 33, 39
};

static const uint8_t e0_feedback_taps[16] = {
    25, 20, 12, 8,
    31, 24, 16, 12,
    33, 28, 24, 4,
    39, 36, 28, 4
};

static const uint8_t e0_output_shifts[4] = {
    23, 22, 29, 28
};

static const uint8_t *register_sizes(void) {
#ifdef CONSTXOR_E0_TABLES
    return constxor_e0_register_sizes();
#else
    return e0_register_sizes;
#endif
}

static const uint8_t *feedback_taps(void) {
#ifdef CONSTXOR_E0_TABLES
    return constxor_e0_feedback_taps();
#else
    return e0_feedback_taps;
#endif
}

static const uint8_t *output_shifts(void) {
#ifdef CONSTXOR_E0_TABLES
    return constxor_e0_output_shifts();
#else
    return e0_output_shifts;
#endif
}

static uint64_t build_mask(uint8_t size) {
    if (size >= 64U) {
        return UINT64_MAX;
    }
    return (UINT64_C(1) << size) - UINT64_C(1);
}

static uint8_t bit_get(uint8_t value, uint8_t index, uint8_t width) {
    return (uint8_t)((value >> (width - index)) & 1U);
}

static void shift_register_feedback(e0_register *reg, const uint8_t taps[4]) {
    uint64_t lsb =
        ((reg->value >> (taps[0] - 1U)) ^
         (reg->value >> (taps[1] - 1U)) ^
         (reg->value >> (taps[2] - 1U)) ^
         (reg->value >> (taps[3] - 1U))) & UINT64_C(1);
    reg->value = ((reg->value << 1) & build_mask(reg->size)) | lsb;
}

static uint8_t st_next(uint8_t input, uint8_t ct) {
    uint8_t yt = bit_get(input, 1, 4) + bit_get(input, 2, 4) + bit_get(input, 3, 4) + bit_get(input, 4, 4);
    return (uint8_t)((yt + ct) / 2U);
}

static uint8_t t2(uint8_t ct) {
    return (uint8_t)(((bit_get(ct, 2, 2) ^ bit_get(ct, 1, 2)) | (ct << 1)) & 3U);
}

static uint8_t ct_next(uint8_t st, uint8_t ct_prev, uint8_t ct_cur) {
    return (uint8_t)(st ^ ct_cur ^ t2(ct_prev));
}

static uint8_t e0_next_state(uint8_t state, uint8_t reg_output) {
    uint8_t ct_cur = (uint8_t)(state >> 2);
    uint8_t ct_prev = (uint8_t)(state & 3U);
    uint8_t st = st_next(reg_output, ct_cur);
    uint8_t ct_new = ct_next(st, ct_prev, ct_cur);
    return (uint8_t)(((ct_new << 2) | ct_cur) & 15U);
}

static uint8_t e0_get_bit_key(uint8_t state, uint8_t reg_output) {
    return (uint8_t)(
        bit_get(reg_output, 1, 4) ^
        bit_get(reg_output, 2, 4) ^
        bit_get(reg_output, 3, 4) ^
        bit_get(reg_output, 4, 4) ^
        bit_get(state, 2, 4)
    );
}

static uint8_t e0_registers_get_output(const e0_state *st) {
    const uint8_t *shifts = output_shifts();
    return (uint8_t)(
        ((st->regs[0].value >> shifts[0]) & UINT64_C(1)) |
        ((st->regs[1].value >> shifts[1]) & UINT64_C(2)) |
        ((st->regs[2].value >> shifts[2]) & UINT64_C(4)) |
        ((st->regs[3].value >> shifts[3]) & UINT64_C(8))
    );
}

static uint8_t e0_registers_shift(e0_state *st) {
    const uint8_t *taps = feedback_taps();
    for (size_t i = 0; i < 4; ++i) {
        shift_register_feedback(&st->regs[i], taps + (i * 4));
    }
    return e0_registers_get_output(st);
}

static uint8_t e0_shift(e0_state *st) {
    uint8_t prev_state = st->state;
    st->reg_output = e0_registers_shift(st);
    st->state = e0_next_state(st->state, st->reg_output);
    st->key_bit = e0_get_bit_key(prev_state, st->reg_output);
    return st->key_bit;
}

static void e0_setup(e0_state *st) {
    const uint8_t *sizes = register_sizes();
    memset(st, 0, sizeof(*st));
    for (size_t i = 0; i < 4; ++i) {
        st->regs[i].size = sizes[i];
    }
}

static void e0_init_state(e0_state *st, const uint8_t key[E0_KEY_BYTES], const uint8_t iv[E0_IV_BYTES]) {
    uint8_t z[17] = {0};
    uint64_t input[4];
    uint8_t saved_state = 0;

    uint8_t clk0 = iv[6];
    uint8_t clk1 = iv[7];
    uint8_t clk2 = iv[8];
    uint8_t clk3 = iv[9];

    e0_setup(st);

    input[0] = ((uint64_t)(clk3 & 1U)) |
               ((uint64_t)key[0] << 1) |
               ((uint64_t)key[4] << 9) |
               ((uint64_t)key[8] << 17) |
               ((uint64_t)key[12] << 25) |
               ((uint64_t)clk1 << 33) |
               ((uint64_t)iv[2] << 41);

    input[1] = UINT64_C(1) |
               ((uint64_t)clk0 << 3) |
               ((uint64_t)key[1] << 7) |
               ((uint64_t)key[5] << 15) |
               ((uint64_t)key[9] << 23) |
               ((uint64_t)key[13] << 31) |
               ((uint64_t)iv[0] << 39) |
               ((uint64_t)iv[3] << 47);

    input[2] = ((uint64_t)(clk3 >> 1)) |
               ((uint64_t)key[2] << 1) |
               ((uint64_t)key[6] << 9) |
               ((uint64_t)key[10] << 17) |
               ((uint64_t)key[14] << 25) |
               ((uint64_t)clk2 << 33) |
               ((uint64_t)iv[4] << 41);

    input[3] = UINT64_C(7) |
               (((uint64_t)(clk0 >> 4)) << 3) |
               ((uint64_t)key[3] << 7) |
               ((uint64_t)key[7] << 15) |
               ((uint64_t)key[11] << 23) |
               ((uint64_t)key[15] << 31) |
               ((uint64_t)iv[1] << 39) |
               ((uint64_t)iv[5] << 47);

    for (int i = 0; i < 240; ++i) {
        if (i < 39) {
            st->state = 0;
        } else if (i == 238) {
            saved_state = st->state;
        }

        e0_shift(st);

        if (i < 25 && (st->regs[0].value & 1U) != 0U) {
            st->regs[0].value--;
        }
        if (i < 31 && (st->regs[1].value & 1U) != 0U) {
            st->regs[1].value--;
        }
        if (i < 33 && (st->regs[2].value & 1U) != 0U) {
            st->regs[2].value--;
        }
        if (i < 39 && (st->regs[3].value & 1U) != 0U) {
            st->regs[3].value--;
        }

        st->regs[0].value ^= (input[0] & UINT64_C(1));
        st->regs[1].value ^= (input[1] & UINT64_C(1));
        st->regs[2].value ^= (input[2] & UINT64_C(1));
        st->regs[3].value ^= (input[3] & UINT64_C(1));

        for (size_t j = 0; j < 4; ++j) {
            input[j] >>= 1;
        }

        if (i >= 111) {
            z[(i - 111) >> 3] = (uint8_t)((z[(i - 111) >> 3] >> 1) | (st->key_bit << 7));
        }
    }

    st->regs[0].value = (uint64_t)z[0] |
                        ((uint64_t)z[4] << 8) |
                        ((uint64_t)z[8] << 16) |
                        (((uint64_t)z[12] & 1U) << 24);

    st->regs[1].value = (uint64_t)z[1] |
                        ((uint64_t)z[5] << 8) |
                        ((uint64_t)z[9] << 16) |
                        (((uint64_t)z[12] >> 1) << 24);

    st->regs[2].value = (uint64_t)z[2] |
                        ((uint64_t)z[6] << 8) |
                        ((uint64_t)z[10] << 16) |
                        ((uint64_t)z[13] << 24) |
                        (((uint64_t)z[15] & 1U) << 32);

    st->regs[3].value = (uint64_t)z[3] |
                        ((uint64_t)z[7] << 8) |
                        ((uint64_t)z[11] << 16) |
                        ((uint64_t)z[14] << 24) |
                        (((uint64_t)z[15] >> 1) << 32);

    st->reg_output = e0_registers_get_output(st);
    st->key_bit = e0_get_bit_key(st->state, st->reg_output);
    st->state = e0_next_state(saved_state, st->reg_output);
}

static uint8_t e0_next_byte(e0_state *st) {
    uint8_t out = 0;
    for (int bit = 0; bit < 8; ++bit) {
        out |= (uint8_t)((st->key_bit & 1U) << bit);
        e0_shift(st);
    }
    return out;
}

void e0_crypt(
    const uint8_t key[E0_KEY_BYTES],
    const uint8_t iv[E0_IV_BYTES],
    const uint8_t *input,
    uint8_t *output,
    size_t len
) {
    e0_state st;
    e0_init_state(&st, key, iv);

    for (size_t i = 0; i < len; ++i) {
        output[i] = (uint8_t)(input[i] ^ e0_next_byte(&st));
    }
}
