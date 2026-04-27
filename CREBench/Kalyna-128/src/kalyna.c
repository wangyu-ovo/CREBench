#include <stdio.h>
#include "kalyna.h"
#include "kalyna-utility.h"

void kalyna_enc(const uint8_t in[KALYNA_BLOCK_BYTES], uint8_t out[KALYNA_BLOCK_BYTES], const uint8_t key[KALYNA_KEY_BYTES]) {
    uint64_t m_rkeys[KALYNA_ROUNDS * 2] = {0}, msg[2] = {0}, t1[2] = {0}, t2[2] = {0};
    kalyna_key_schedule(m_rkeys, key);
    // printf("Round keys:\n");
    // for (int i = 0; i < KALYNA_ROUNDS * 2; i++) {
    //     printf("%llx ", m_rkeys[i]);
    // }
    for (int i = 0; i < KALYNA_BLOCK_BYTES; i++) {
        msg[i / 8] |= (uint64_t)in[i] << (8 * (i % 8)); // little-endian
    }
    // for (int i = 0; i < KALYNA_BLOCK_BYTES / 8; i++) {
    //     printf("msg[%d]: %llx\n", i, msg[i]);
    // }
    AddKey(msg, t1, m_rkeys, 2);
    G128(t1, t2, &m_rkeys[2]);   // 1
    G128(t2, t1, &m_rkeys[4]);   // 2
    G128(t1, t2, &m_rkeys[6]);   // 3
    G128(t2, t1, &m_rkeys[8]);   // 4
    G128(t1, t2, &m_rkeys[10]);  // 5
    G128(t2, t1, &m_rkeys[12]);  // 6
    G128(t1, t2, &m_rkeys[14]);  // 7
    G128(t2, t1, &m_rkeys[16]);  // 8
    G128(t1, t2, &m_rkeys[18]);  // 9
    GL128(t2, t1, &m_rkeys[20]); // 10
    for (int i = 0; i < KALYNA_BLOCK_BYTES; i++) {
        out[i] = (t1[i / 8] >> (8 * (i % 8))) & 0xFF; // little-endian
    }
}
