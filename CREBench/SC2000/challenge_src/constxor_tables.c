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

static const uint32_t S6_xor_lhs[64] = {
    0xFFF9CB24U, 0xAFB62BD7U, 0x9B7BE4C2U, 0x81E54E0DU, 0xA8C11516U, 0x89EC94D0U,
    0xFAFAA254U, 0x755FBB49U, 0xBA7383B0U, 0xEDFB32A5U, 0xB0E65FCBU, 0x4F57F84AU,
    0xEC0608B3U, 0xC1263CA9U, 0xCB877E7AU, 0xF465FE6AU, 0xE275E85BU, 0x6337A927U,
    0x687FFB94U, 0x56CB2610U, 0x6357D52FU, 0xAD73F166U, 0x720867D5U, 0x740EF3AAU,
    0x0B151697U, 0x0C8E1382U, 0x7584DA00U, 0xB1E6D21CU, 0x35CD019CU, 0xBDDB0158U,
    0x77F12E46U, 0x75C0279CU, 0x79010677U, 0x2D56DAFDU, 0xF7A532B2U, 0x9ABC7F7DU,
    0x56F89F16U, 0x5B95C336U, 0xD5E0780AU, 0x35D475C2U, 0xA2898000U, 0x54DF031CU,
    0xA474228BU, 0x8972708DU, 0x971ED7F2U, 0x43C3326EU, 0x983C71F6U, 0x33AA2771U,
    0x3A2761CAU, 0x6256AAF4U, 0x3D538456U, 0x6ECC8DF2U, 0xB20B899FU, 0x4B4DB158U,
    0x4D69E05DU, 0xD2BD63ECU, 0x4E3C9F95U, 0x7D5FE5E4U, 0x6BF45AF7U, 0x5D66BF4EU,
    0xFCCE26CAU, 0x25CCF2D6U, 0xC3E0D41FU, 0x49F73E3BU
};

static const uint32_t S6_xor_rhs[64] = {
    0xFFF9CB0BU, 0xAFB62BECU, 0x9B7BE4DBU, 0x81E54E27U, 0xA8C11519U, 0x89EC94C7U,
    0xFAFAA248U, 0x755FBB6EU, 0xBA7383AAU, 0xEDFB3283U, 0xB0E65FEFU, 0x4F57F859U,
    0xEC06088FU, 0xC1263CB1U, 0xCB877E67U, 0xF465FE52U, 0xE275E87EU, 0x6337A918U,
    0x687FFB80U, 0x56CB262DU, 0x6357D518U, 0xAD73F164U, 0x720867CBU, 0x740EF386U,
    0x0B15169EU, 0x0C8E1388U, 0x7584DA06U, 0xB1E6D20AU, 0x35CD01A9U, 0xBDDB0168U,
    0x77F12E75U, 0x75C02797U, 0x79010649U, 0x2D56DAC9U, 0xF7A53291U, 0x9ABC7F6FU,
    0x56F89F18U, 0x5B95C318U, 0xD5E0780AU, 0x35D475F4U, 0xA2898011U, 0x54DF0334U,
    0xA4742290U, 0x89727089U, 0x971ED7EDU, 0x43C33266U, 0x983C71F3U, 0x33AA277DU,
    0x3A2761C9U, 0x6256AAE4U, 0x3D53847FU, 0x6ECC8DD0U, 0xB20B89BEU, 0x4B4DB15FU,
    0x4D69E070U, 0xD2BD63DDU, 0x4E3C9FA7U, 0x7D5FE5DEU, 0x6BF45AF6U, 0x5D66BF5BU,
    0xFCCE26E1U, 0x25CCF2EFU, 0xC3E0D43FU, 0x49F73E36U
};

static uint32_t S6_decoded[64];
static int S6_ready;

__attribute__((noinline, noclone))
static void ensure_S6_decoded(void) {
    if (S6_ready) {
        return;
    }
    constxor_compiler_barrier();
    materialize_u32_table(S6_xor_lhs, S6_xor_rhs, S6_decoded, 64);
    constxor_compiler_barrier();
    S6_ready = 1;
}

const uint32_t *constxor_sc2000_s6(void) {
    ensure_S6_decoded();
    return S6_decoded;
}

static const uint32_t S5_xor_lhs[32] = {
    0x03AB78B8U, 0x42E6FDB3U, 0x90B6F60AU, 0x50A720F1U, 0x6F2D5446U, 0x82ADE2D2U,
    0x83541056U, 0x8E84DB67U, 0xC3389E64U, 0xEC133D8DU, 0xF7ADE4AAU, 0x5EFDFA3CU,
    0x164451BFU, 0x914F5C3FU, 0xBB1C6535U, 0xE72F5833U, 0x2B1CC257U, 0xB9CBDB49U,
    0xDDCA9AE0U, 0x2158177BU, 0x2E124D87U, 0x12D37EF2U, 0xEC48ADC9U, 0x943C1353U,
    0x4CF47E8EU, 0xE807D4ABU, 0x3D1E9E8AU, 0x7BCF3067U, 0x985F10A2U, 0xA48ECF06U,
    0xB1108DF2U, 0x95FA5C35U
};

static const uint32_t S5_xor_rhs[32] = {
    0x03AB78ACU, 0x42E6FDA9U, 0x90B6F60DU, 0x50A720EEU, 0x6F2D5455U, 0x82ADE2DEU,
    0x8354105CU, 0x8E84DB68U, 0xC3389E72U, 0xEC133D93U, 0xF7ADE4A7U, 0x5EFDFA32U,
    0x164451BBU, 0x914F5C27U, 0xBB1C653CU, 0xE72F5821U, 0x2B1CC24CU, 0xB9CBDB42U,
    0xDDCA9AE1U, 0x2158176EU, 0x2E124D81U, 0x12D37EE2U, 0xEC48ADCBU, 0x943C134FU,
    0x4CF47E99U, 0xE807D4AEU, 0x3D1E9E82U, 0x7BCF3064U, 0x985F10A2U, 0xA48ECF17U,
    0xB1108DEFU, 0x95FA5C2CU
};

static uint32_t S5_decoded[32];
static int S5_ready;

__attribute__((noinline, noclone))
static void ensure_S5_decoded(void) {
    if (S5_ready) {
        return;
    }
    constxor_compiler_barrier();
    materialize_u32_table(S5_xor_lhs, S5_xor_rhs, S5_decoded, 32);
    constxor_compiler_barrier();
    S5_ready = 1;
}

const uint32_t *constxor_sc2000_s5(void) {
    ensure_S5_decoded();
    return S5_decoded;
}

static const uint32_t S4_xor_lhs[16] = {
    0x1A84F08EU, 0x6FDEF323U, 0xD27DA3F8U, 0xF531A125U, 0x46B4C2F6U, 0xAA1EF5CBU,
    0x3537ACDBU, 0xDA3D1200U, 0x4A79EB69U, 0x1374CD0CU, 0xAE82AC64U, 0x06B67A98U,
    0xB729BE21U, 0xC7326B67U, 0x098EC874U, 0xC09F947DU
};

static const uint32_t S4_xor_rhs[16] = {
    0x1A84F08CU, 0x6FDEF326U, 0xD27DA3F2U, 0xF531A129U, 0x46B4C2F1U, 0xAA1EF5C4U,
    0x3537ACDAU, 0xDA3D120BU, 0x4A79EB64U, 0x1374CD0AU, 0xAE82AC64U, 0x06B67A91U,
    0xB729BE25U, 0xC7326B6FU, 0x098EC877U, 0xC09F9473U
};

static uint32_t S4_decoded[16];
static int S4_ready;

__attribute__((noinline, noclone))
static void ensure_S4_decoded(void) {
    if (S4_ready) {
        return;
    }
    constxor_compiler_barrier();
    materialize_u32_table(S4_xor_lhs, S4_xor_rhs, S4_decoded, 16);
    constxor_compiler_barrier();
    S4_ready = 1;
}

const uint32_t *constxor_sc2000_s4(void) {
    ensure_S4_decoded();
    return S4_decoded;
}

static const uint32_t S4i_xor_lhs[16] = {
    0xC910720CU, 0xCF4F151FU, 0xD5F4E0A8U, 0xFBB6CAA4U, 0x94A244E2U, 0xFB87781DU,
    0x897A5A7FU, 0x6B2245E6U, 0x63CDCF61U, 0x5D90D327U, 0x73F56630U, 0x40A38CACU,
    0x0BBF9254U, 0xC7A00A1EU, 0x3E869636U, 0xA0AEE89CU
};

static const uint32_t S4i_xor_rhs[16] = {
    0xC9107206U, 0xCF4F1519U, 0xD5F4E0A8U, 0xFBB6CAAAU, 0x94A244EEU, 0xFB87781CU,
    0x897A5A76U, 0x6B2245E2U, 0x63CDCF6CU, 0x5D90D32CU, 0x73F56632U, 0x40A38CABU,
    0x0BBF9257U, 0xC7A00A16U, 0x3E869639U, 0xA0AEE899U
};

static uint32_t S4i_decoded[16];
static int S4i_ready;

__attribute__((noinline, noclone))
static void ensure_S4i_decoded(void) {
    if (S4i_ready) {
        return;
    }
    constxor_compiler_barrier();
    materialize_u32_table(S4i_xor_lhs, S4i_xor_rhs, S4i_decoded, 16);
    constxor_compiler_barrier();
    S4i_ready = 1;
}

const uint32_t *constxor_sc2000_s4i(void) {
    ensure_S4i_decoded();
    return S4i_decoded;
}

static const uint32_t M_xor_lhs[32] = {
    0xAE666DBEU, 0x9CDE2D5AU, 0x08FEA47EU, 0xB26E0EF9U, 0xEF2C6C8BU, 0x41C06CF2U,
    0x9AB70201U, 0x4C8B1DCFU, 0x04222DD5U, 0xE8A31BFAU, 0xBB5B8EC8U, 0x84905C2CU,
    0xF9D38C8CU, 0xB0F32E13U, 0x2D190AF2U, 0xCD9468E7U, 0x4090AEF9U, 0x10C9D9DFU,
    0x5F10AA19U, 0x63E0705FU, 0x730A8B62U, 0x111F6513U, 0x582D35FAU, 0x4E6027FCU,
    0x86066B0CU, 0x871895C2U, 0x552EA44DU, 0x50F2F34DU, 0x402F83E9U, 0x1C2D6B71U,
    0xBCC1FE5FU, 0x25CD9BD9U
};

static const uint32_t M_xor_rhs[32] = {
    0x7EA7FF9BU, 0x397C0950U, 0x137A762EU, 0x0546AA58U, 0x855C2589U, 0xC41DB714U,
    0xECD8F6A5U, 0xA054FCE7U, 0xABF31341U, 0x372066F3U, 0x007C749AU, 0xEDC00580U,
    0xAB7237D4U, 0x7CC1010EU, 0x355D5CA9U, 0x793CC411U, 0x74B3FAC1U, 0x788E718EU,
    0xBB9CA6A2U, 0xAEF86169U, 0xE91BA16EU, 0x52F3081DU, 0xDFF5E787U, 0x061DEE69U,
    0x16FDF047U, 0x26EEA355U, 0xA97F9A94U, 0x28518EDEU, 0xCD394636U, 0x8221E0CFU,
    0x80F9E123U, 0xCC369CA0U
};

static uint32_t M_decoded[32];
static int M_ready;

__attribute__((noinline, noclone))
static void ensure_M_decoded(void) {
    if (M_ready) {
        return;
    }
    constxor_compiler_barrier();
    materialize_u32_table(M_xor_lhs, M_xor_rhs, M_decoded, 32);
    constxor_compiler_barrier();
    M_ready = 1;
}

const uint32_t *constxor_sc2000_m(void) {
    ensure_M_decoded();
    return M_decoded;
}
