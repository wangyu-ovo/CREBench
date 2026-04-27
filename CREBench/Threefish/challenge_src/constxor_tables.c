#include "constxor_tables.h"

#include <stddef.h>

__attribute__((noinline, noclone))
static void constxor_compiler_barrier(void) {
    __asm__ __volatile__("" ::: "memory");
}

__attribute__((noinline, noclone))
static void materialize_u8_table(const uint8_t *lhs_raw, const uint8_t *rhs_raw, uint8_t *out, size_t count) {
    const volatile uint8_t *lhs = (const volatile uint8_t *)lhs_raw;
    const volatile uint8_t *rhs = (const volatile uint8_t *)rhs_raw;
    constxor_compiler_barrier();
    for (size_t i = 0; i < count; ++i) {
        out[i] = (uint8_t)(lhs[i] ^ rhs[i]);
    }
    constxor_compiler_barrier();
}

__attribute__((noinline, noclone))
static void materialize_u16_table(const uint16_t *lhs_raw, const uint16_t *rhs_raw, uint16_t *out, size_t count) {
    const volatile uint16_t *lhs = (const volatile uint16_t *)lhs_raw;
    const volatile uint16_t *rhs = (const volatile uint16_t *)rhs_raw;
    constxor_compiler_barrier();
    for (size_t i = 0; i < count; ++i) {
        out[i] = (uint16_t)(lhs[i] ^ rhs[i]);
    }
    constxor_compiler_barrier();
}

__attribute__((noinline, noclone))
static void materialize_u64_table(const uint64_t *lhs_raw, const uint64_t *rhs_raw, uint64_t *out, size_t count) {
    const volatile uint64_t *lhs = (const volatile uint64_t *)lhs_raw;
    const volatile uint64_t *rhs = (const volatile uint64_t *)rhs_raw;
    constxor_compiler_barrier();
    for (size_t i = 0; i < count; ++i) {
        out[i] = lhs[i] ^ rhs[i];
    }
    constxor_compiler_barrier();
}

__attribute__((noinline, noclone))
static void materialize_u32_table(const uint32_t *lhs_raw, const uint32_t *rhs_raw, uint32_t *out, size_t count) {
    const volatile uint32_t *lhs = (const volatile uint32_t *)lhs_raw;
    const volatile uint32_t *rhs = (const volatile uint32_t *)rhs_raw;
    constxor_compiler_barrier();
    for (size_t i = 0; i < count; ++i) {
        out[i] = lhs[i] ^ rhs[i];
    }
    constxor_compiler_barrier();
}

static const uint64_t threefish_c240_xor_lhs[1] = {
    0xB5D191892A1A48B1ULL
};

static const uint64_t threefish_c240_xor_rhs[1] = {
    0xAE008A5383E65293ULL
};

static uint64_t threefish_c240_decoded[1];
static int threefish_c240_ready;

__attribute__((noinline, noclone))
static void ensure_threefish_c240_decoded(void) {
    if (threefish_c240_ready) {
        return;
    }
    constxor_compiler_barrier();
    materialize_u64_table(threefish_c240_xor_lhs, threefish_c240_xor_rhs, threefish_c240_decoded, 1);
    constxor_compiler_barrier();
    threefish_c240_ready = 1;
}

const uint64_t *constxor_threefish_c240(void) {
    ensure_threefish_c240_decoded();
    return threefish_c240_decoded;
}

static const uint8_t r512_xor_lhs[32] = {
    0xBF, 0xE1, 0x6A, 0xEF, 0xFA, 0xF5, 0x6C, 0x33, 0x32, 0x05, 0xA8, 0xC1, 0x1B, 0xD8, 0x77, 0xA2,
    0x7C, 0x46, 0xCA, 0x52, 0xBE, 0x19, 0x37, 0xF7, 0x19, 0x75, 0x21, 0x5C, 0x59, 0xE6, 0x80, 0x1A
};

static const uint8_t r512_xor_rhs[32] = {
    0x91, 0xC5, 0x79, 0xCA, 0xDB, 0xEE, 0x62, 0x19, 0x23, 0x34, 0x8C, 0xE6, 0x37, 0xD1, 0x41, 0x9A,
    0x5B, 0x58, 0xE8, 0x4A, 0xB3, 0x2B, 0x3D, 0xE6, 0x00, 0x68, 0x06, 0x77, 0x51, 0xC5, 0xB8, 0x0C
};

static uint8_t r512_decoded[32];
static int r512_ready;

__attribute__((noinline, noclone))
static void ensure_r512_decoded(void) {
    if (r512_ready) {
        return;
    }
    constxor_compiler_barrier();
    materialize_u8_table(r512_xor_lhs, r512_xor_rhs, r512_decoded, 32);
    constxor_compiler_barrier();
    r512_ready = 1;
}

const uint8_t *constxor_threefish_r512(void) {
    ensure_r512_decoded();
    return r512_decoded;
}

static const uint8_t p512_xor_lhs[8] = {
    0x96, 0xB0, 0xDA, 0xB7, 0x27, 0x2D, 0x65, 0x52
};

static const uint8_t p512_xor_rhs[8] = {
    0x90, 0xB1, 0xDA, 0xB0, 0x25, 0x28, 0x61, 0x51
};

static uint8_t p512_decoded[8];
static int p512_ready;

__attribute__((noinline, noclone))
static void ensure_p512_decoded(void) {
    if (p512_ready) {
        return;
    }
    constxor_compiler_barrier();
    materialize_u8_table(p512_xor_lhs, p512_xor_rhs, p512_decoded, 8);
    constxor_compiler_barrier();
    p512_ready = 1;
}

const uint8_t *constxor_threefish_p512(void) {
    ensure_p512_decoded();
    return p512_decoded;
}
