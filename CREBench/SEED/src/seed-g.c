#include "seed.h"

#ifdef CONSTXOR_SEED_TABLES
#include "constxor_tables.h"
#define SEED_S0_TABLE (constxor_seed_s0())
#define SEED_S1_TABLE (constxor_seed_s1())
#else
extern const uint8_t s_s0[256], s_s1[256];
#define SEED_S0_TABLE (s_s0)
#define SEED_S1_TABLE (s_s1)
#endif

#define GETBYTE(x, y) (uint8_t)((x)>>(8*(y)))

uint32_t G(uint32_t x) {
    uint8_t b0 = GETBYTE(x, 0);
    uint8_t b1 = GETBYTE(x, 1);
    uint8_t b2 = GETBYTE(x, 2);
    uint8_t b3 = GETBYTE(x, 3);

    uint32_t s0 = (SEED_S0_TABLE[b0] * 0x01010101UL) & 0x3FCFF3FC;
    uint32_t s1 = (SEED_S1_TABLE[b1] * 0x01010101UL) & 0xFC3FCFF3;
    uint32_t s2 = (SEED_S0_TABLE[b2] * 0x01010101UL) & 0xF3FC3FCF;
    uint32_t s3 = (SEED_S1_TABLE[b3] * 0x01010101UL) & 0xCFF3FC3F;

    return s0 ^ s1 ^ s2 ^ s3;
}
