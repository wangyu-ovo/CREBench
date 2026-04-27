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

static const uint32_t shacal2_rc_xor_lhs[64] = {
    0x80E3BE6BU, 0x9F022631U, 0xE16B50C4U, 0x5E31C875U, 0xC0226592U, 0x2CAEAE94U,
    0x098C3133U, 0x37DBB642U, 0xE8E746FFU, 0x0ED678FFU, 0xA2EC3FC7U, 0x29409124U,
    0xC0DF4932U, 0x94D7BE1DU, 0x79FCB4A0U, 0x6F71C5F8U, 0xC38ACC7EU, 0x96F3CFA9U,
    0xE0671AF7U, 0xA8BCCEB1U, 0x8FCD0A6CU, 0x8F10ABC1U, 0x11D8B7A6U, 0x51A72798U,
    0x0BC4EF9BU, 0x77D120E8U, 0xB4378C86U, 0x32548951U, 0x597453FDU, 0xC9E2CE5AU,
    0xCF0F9752U, 0xAFEE044DU, 0x7C02935FU, 0x1C394936U, 0xC94387E1U, 0x73EF8505U,
    0xEEA62099U, 0x4CA3BF0AU, 0x981A6904U, 0xBE0934A7U, 0x90FE0C50U, 0xFABE83E5U,
    0x56366126U, 0x56842F26U, 0x02853880U, 0xE0687094U, 0xF4590C5EU, 0x63B571C5U,
    0x5A28064AU, 0x65ECA8E9U, 0xD6657EA6U, 0xBE6D6C38U, 0x54923351U, 0x58BBDDE5U,
    0x778F758FU, 0xAA9CACA6U, 0x17C69C46U, 0x84E95062U, 0xD497AD8AU, 0x68C5817EU,
    0x7FF13569U, 0xF42FFBE4U, 0x5D7814F9U, 0x153B6ADAU
};

static const uint32_t shacal2_rc_xor_rhs[64] = {
    0xC26991F3U, 0xEE3562A0U, 0x54ABAB0BU, 0xB78413D0U, 0xF974A7C9U, 0x755FBF65U,
    0x9BB3B397U, 0x9CC7E897U, 0x30E0EC67U, 0x1C5523FEU, 0x86DDBA79U, 0x7C4CECE7U,
    0xB2611446U, 0x14090FE3U, 0xE220B207U, 0xAEEA348CU, 0x2711A5BFU, 0x794D882FU,
    0xEFA68731U, 0x8CB06F7DU, 0xA2242603U, 0xC5642F6BU, 0x4D681E7AU, 0x275EAF42U,
    0x93FABEC9U, 0xDFE0E685U, 0x0434AB4EU, 0x8D0DF696U, 0x9F94580EU, 0x1C455F1DU,
    0xC9C5F403U, 0xBBC72D2AU, 0x5BB599DAU, 0x3222680EU, 0x846FEA1DU, 0x20D78816U,
    0x8BAC53CDU, 0x3AC9B5B1U, 0x19D8A02AU, 0x2C7B1822U, 0x3241E4F1U, 0x52A4E5AEU,
    0x947DEA56U, 0x91E87E85U, 0xD317D099U, 0x36F176B0U, 0x005739DBU, 0x73DFD1B5U,
    0x438CC75CU, 0x7BDBC4E1U, 0xF12D09EAU, 0x8ADDD08DU, 0x6D8E3FE2U, 0x166377AFU,
    0x2C13BFC0U, 0xC2B2C355U, 0x63491EA8U, 0xFC4C330DU, 0x505FD59EU, 0xE4028376U,
    0xEF4FCA93U, 0x507F970FU, 0xE381B70EU, 0xD34A1228U
};

static uint32_t shacal2_rc_decoded[64];
static int shacal2_rc_ready;

__attribute__((noinline, noclone))
static void ensure_shacal2_rc_decoded(void) {
    if (shacal2_rc_ready) {
        return;
    }
    constxor_compiler_barrier();
    materialize_u32_table(shacal2_rc_xor_lhs, shacal2_rc_xor_rhs, shacal2_rc_decoded, 64);
    constxor_compiler_barrier();
    shacal2_rc_ready = 1;
}

const uint32_t *constxor_shacal2_rc(void) {
    ensure_shacal2_rc_decoded();
    return shacal2_rc_decoded;
}
