#include <stdio.h>
#include "seed.h"

#ifdef CONSTXOR_SEED_TABLES
#include "constxor_tables.h"
#define SEED_KC_TABLE (constxor_seed_kc())
#else
extern const uint32_t s_kc[16];
#define SEED_KC_TABLE (s_kc)
#endif
extern uint32_t G(uint32_t x);

void seed_key_schedule(const uint8_t key[SEED_KEY_BYTES], uint32_t m_k[SEED_ROUNDS * 2]) {
    uint64_t key01, key23;
    key01 = ((uint64_t)key[0] << 56) | ((uint64_t)key[1] << 48) | ((uint64_t)key[2] << 40) | ((uint64_t)key[3] << 32) | 
             ((uint64_t)key[4] << 24) | ((uint64_t)key[5] << 16) | ((uint64_t)key[6] << 8) | ((uint64_t)key[7]);
    key23 = ((uint64_t)key[8] << 56) | ((uint64_t)key[9] << 48) | ((uint64_t)key[10] << 40) | ((uint64_t)key[11] << 32) | 
             ((uint64_t)key[12] << 24) | ((uint64_t)key[13] << 16) | ((uint64_t)key[14] << 8) | ((uint64_t)key[15]);

    for (int i = 0; i < SEED_ROUNDS; i++) {
        uint32_t t0 = (uint32_t)(key01 >> 32) + (uint32_t)(key23 >> 32) - SEED_KC_TABLE[i];
        uint32_t t1 = (uint32_t)key01 - (uint32_t)key23 + SEED_KC_TABLE[i];
        m_k[2*i] = G(t0);
        m_k[2*i + 1] = G(t1);
        // printf("Round %d: key01 = %016llx, key23 = %016llx, t0 = %08x, t1 = %08x\n",
        //        i, key01, key23, t0, t1);
        if (i % 2 == 1) {
            key23 = (key23 << 8) | (key23 >> (64 - 8)); // rotate left 8 bits
        } else {
            key01 = (key01 >> 8) | (key01 << (64 - 8)); // rotate right 8 bits
        }
    }
    // for(int i = 0; i < SEED_ROUNDS * 2; i++) {
    //     printf("%08x,", m_k[i]);
    // }
}
