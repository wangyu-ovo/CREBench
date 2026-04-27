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

static const uint32_t speck_round_constants_xor_lhs[26] = {
    0x724A96ACU, 0x31443099U, 0xF7CE6272U, 0xA40DB396U, 0x35671F81U, 0x380E41C0U,
    0xA8341B83U, 0x973A9175U, 0x3E9E9AAAU, 0x79850ECCU, 0x40574B41U, 0x2BE89C67U,
    0xF089190BU, 0x8A29B67FU, 0x9B69CCD4U, 0xAEBC6946U, 0x6D39754BU, 0x437AE543U,
    0x77B6395CU, 0xFCB5218AU, 0xFE59DA41U, 0xF0A7E8C8U, 0x8A3C0373U, 0x535250B7U,
    0xA5929279U, 0x030EA8DEU
};

static const uint32_t speck_round_constants_xor_rhs[26] = {
    0x724A96ACU, 0x31443098U, 0xF7CE6270U, 0xA40DB395U, 0x35671F85U, 0x380E41C5U,
    0xA8341B85U, 0x973A9172U, 0x3E9E9AA2U, 0x79850EC5U, 0x40574B4BU, 0x2BE89C6CU,
    0xF0891907U, 0x8A29B672U, 0x9B69CCDAU, 0xAEBC6949U, 0x6D39755BU, 0x437AE552U,
    0x77B6394EU, 0xFCB52199U, 0xFE59DA55U, 0xF0A7E8DDU, 0x8A3C0365U, 0x535250A0U,
    0xA5929261U, 0x030EA8C7U
};

static uint32_t speck_round_constants_decoded[26];
static int speck_round_constants_ready;

__attribute__((noinline, noclone))
static void ensure_speck_round_constants_decoded(void) {
    if (speck_round_constants_ready) {
        return;
    }
    constxor_compiler_barrier();
    materialize_u32_table(speck_round_constants_xor_lhs, speck_round_constants_xor_rhs, speck_round_constants_decoded, 26);
    constxor_compiler_barrier();
    speck_round_constants_ready = 1;
}

const uint32_t *constxor_speck_round_constants(void) {
    ensure_speck_round_constants_decoded();
    return speck_round_constants_decoded;
}
