#include "idea.h"

extern uint16_t MulInv(uint16_t x);
extern uint16_t AddInv(uint16_t x);

void idea_key_schedule(const uint8_t key[IDEA_KEY_BYTES], uint16_t m_k[IDEA_TRANSFORMED_KEY_WORDS]) {
    uint16_t k[IDEA_TRANSFORMED_KEY_WORDS];
    for (int i = 0; i < 8; i++)
		k[i] = ((uint16_t)key[2*i]<<8) | key[2*i+1];
    for (int i = 8; i < IDEA_TRANSFORMED_KEY_WORDS; i++) {
        int j = (i - 8) / 8 * 8;
        k[i] = ((k[j+(i+1)%8] << 9) | (k[j+(i+2)%8] >> 7));
    }
	for (int i = 0; i < IDEA_TRANSFORMED_KEY_WORDS; i++) {
		m_k[i] = k[i];
	}
    // for (int i=0; i<=IDEA_ROUNDS; i++)
	// {
	// 	m_k[i*6+0] = MulInv(k[(IDEA_ROUNDS-i)*6+0]);
	// 	m_k[i*6+1] = AddInv(k[(IDEA_ROUNDS-i)*6+1+(i>0)]);
	// 	m_k[i*6+2] = AddInv(k[(IDEA_ROUNDS-i)*6+2-(i>0)]);
	// 	m_k[i*6+3] = MulInv(k[(IDEA_ROUNDS-i)*6+3]);
    //     if (i == IDEA_ROUNDS) break;
	// 	m_k[i*6+4] =        k[(IDEA_ROUNDS-1-i)*6+4];
	// 	m_k[i*6+5] =        k[(IDEA_ROUNDS-1-i)*6+5];
	// }
}