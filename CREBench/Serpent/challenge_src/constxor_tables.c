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

static const uint32_t serpent_magic_xor_lhs[1] = {
    0x9729A125U
};

static const uint32_t serpent_magic_xor_rhs[1] = {
    0x091ED89CU
};

static uint32_t serpent_magic_decoded[1];
static int serpent_magic_ready;

__attribute__((noinline, noclone))
static void ensure_serpent_magic_decoded(void) {
    if (serpent_magic_ready) {
        return;
    }
    constxor_compiler_barrier();
    materialize_u32_table(serpent_magic_xor_lhs, serpent_magic_xor_rhs, serpent_magic_decoded, 1);
    constxor_compiler_barrier();
    serpent_magic_ready = 1;
}

const uint32_t *constxor_serpent_magic(void) {
    ensure_serpent_magic_decoded();
    return serpent_magic_decoded;
}
