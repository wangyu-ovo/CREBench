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

static const uint8_t rc_table_xor_lhs[17] = {
    0x40, 0x01, 0x7E, 0x43, 0x70, 0x7E, 0xB9, 0x21, 0xD7, 0x9B, 0x50, 0x1A, 0x96, 0xE4, 0x59, 0xE2,
    0xA1
};

static const uint8_t rc_table_xor_rhs[17] = {
    0xC0, 0x1A, 0x48, 0x2F, 0xA8, 0xD5, 0xF4, 0xBB, 0xF8, 0xC5, 0xEC, 0x79, 0x50, 0x73, 0x6C, 0x88,
    0x75
};

static uint8_t rc_table_decoded[17];
static int rc_table_ready;

__attribute__((noinline, noclone))
static void ensure_rc_table_decoded(void) {
    if (rc_table_ready) {
        return;
    }
    constxor_compiler_barrier();
    materialize_u8_table(rc_table_xor_lhs, rc_table_xor_rhs, rc_table_decoded, 17);
    constxor_compiler_barrier();
    rc_table_ready = 1;
}

const uint8_t *constxor_noekeon_rc(void) {
    ensure_rc_table_decoded();
    return rc_table_decoded;
}
