#include "seed.h"

extern void seed_key_schedule(const uint8_t key[SEED_KEY_BYTES], uint32_t m_k[SEED_ROUNDS * 2]);
extern uint32_t G(uint32_t x);

void seed_enc(const uint8_t in[SEED_BLOCK_BYTES], uint8_t out[SEED_BLOCK_BYTES], const uint8_t key[SEED_KEY_BYTES]) {
    uint32_t m_k[SEED_ROUNDS * 2];
    seed_key_schedule(key, m_k);
    uint32_t a0, a1, b0, b1, t0, t1;
    a0 = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
    a1 = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) | ((uint32_t)in[6] << 8) | (uint32_t)in[7];
    b0 = ((uint32_t)in[8] << 24) | ((uint32_t)in[9] << 16) | ((uint32_t)in[10] << 8) | (uint32_t)in[11];
    b1 = ((uint32_t)in[12] << 24) | ((uint32_t)in[13] << 16) | ((uint32_t)in[14] << 8) | (uint32_t)in[15];
    
    // encryption rounds
    for (int i = 0; i < SEED_ROUNDS; i+=2) {
		t0 = b0 ^ m_k[2*i+0]; t1 = b1 ^ m_k[2*i+1] ^ t0;
		t1 = G(t1); t0 += t1; t0 = G(t0); t1 += t0; t1 = G(t1);
		a0 ^= t0 + t1; a1 ^= t1;

		t0 = a0 ^ m_k[2*i+2]; t1 = a1 ^ m_k[2*i+3] ^ t0;
		t1 = G(t1); t0 += t1; t0 = G(t0); t1 += t0; t1 = G(t1);
		b0 ^= t0 + t1; b1 ^= t1;
	}

    // swap a0<->b0, a1<->b1 and store output
    out[0] = (b0 >> 24) & 0xFF;
    out[1] = (b0 >> 16) & 0xFF;
    out[2] = (b0 >> 8) & 0xFF;
    out[3] = b0 & 0xFF;
    out[4] = (b1 >> 24) & 0xFF;
    out[5] = (b1 >> 16) & 0xFF;
    out[6] = (b1 >> 8) & 0xFF;
    out[7] = b1 & 0xFF;
    out[8] = (a0 >> 24) & 0xFF;
    out[9] = (a0 >> 16) & 0xFF;
    out[10] = (a0 >> 8) & 0xFF;
    out[11] = a0 & 0xFF;
    out[12] = (a1 >> 24) & 0xFF;
    out[13] = (a1 >> 16) & 0xFF;
    out[14] = (a1 >> 8) & 0xFF;
    out[15] = a1 & 0xFF;
}