#include <stdio.h>
#include "idea.h"

extern void idea_key_schedule(const uint8_t key[IDEA_KEY_BYTES], uint16_t m_k[IDEA_TRANSFORMED_KEY_WORDS]);
extern uint16_t MUL(uint16_t a, uint16_t b);

void idea_enc(const uint8_t in[IDEA_BLOCK_BYTES], uint8_t out[IDEA_BLOCK_BYTES], const uint8_t key[IDEA_KEY_BYTES]) {
    uint16_t m_k[IDEA_TRANSFORMED_KEY_WORDS];
    idea_key_schedule(key, m_k);
    // for (int i = 0; i < IDEA_TRANSFORMED_KEY_WORDS; i++) {
    //     printf("m_k[%d] = %04x, ", i, m_k[i]);
    //     if (i % 4 == 3)
    //         printf("\n");
    // }
    uint16_t x0, x1, x2, x3, t0, t1;
    x0 = ((uint16_t)in[0] << 8) | in[1];
    x1 = ((uint16_t)in[2] << 8) | in[3];
    x2 = ((uint16_t)in[4] << 8) | in[5];
    x3 = ((uint16_t)in[6] << 8) | in[7];
    
    // encryption rounds
    for (unsigned int i=0; i < IDEA_ROUNDS; i++)
	{
		x0 = MUL(x0, m_k[i*6+0]);
		x1 += m_k[i*6+1];
		x2 += m_k[i*6+2];
		x3 = MUL(x3, m_k[i*6+3]);
		t0 = x0^x2;
		t0 = MUL(t0, m_k[i*6+4]);
		t1 = t0 + (x1^x3);
		t1 = MUL(t1, m_k[i*6+5]);
		t0 += t1;
		x0 ^= t1;
		x3 ^= t0;
		t0 ^= x1;
		x1 = x2^t1;
		x2 = t0;
        // printf("After round %d: x0=%x, x1=%x, x2=%x, x3=%x, t0=%x, t1=%x\n", i+1, x0, x1, x2, x3, t0, t1);
	}
	x0 = MUL(x0, m_k[IDEA_ROUNDS*6+0]);
	x2 += m_k[IDEA_ROUNDS*6+1];
	x1 += m_k[IDEA_ROUNDS*6+2];
	x3 = MUL(x3, m_k[IDEA_ROUNDS*6+3]);
    // printf("After final transformation: x0=%x, x1=%x, x2=%x, x3=%x\n", x0, x1, x2, x3);

    // store output in the order (x0, x2, x1, x3)
    out[0] = (x0 >> 8) & 0xFF;
    out[1] = x0 & 0xFF;
    out[2] = (x2 >> 8) & 0xFF;
    out[3] = x2 & 0xFF;
    out[4] = (x1 >> 8) & 0xFF;
    out[5] = x1 & 0xFF;
    out[6] = (x3 >> 8) & 0xFF;
    out[7] = x3 & 0xFF;
}