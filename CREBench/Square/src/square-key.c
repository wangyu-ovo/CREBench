#include <stdio.h>
#include "square.h"

extern uint16_t MulInv(uint16_t x);
extern uint16_t AddInv(uint16_t x);


#define roundkeys(i, j)		m_k[(i)*4+(j)]
#define roundkeys4(i)       (m_k+(i)*4)

uint32_t rotl(uint32_t x, unsigned int n) { // bit left rotation
    return (x << n) | (x >> (32 - n));
}

void square_key_schedule(const uint8_t key[SQUARE_KEY_BYTES], uint32_t m_k[SQUARE_TRANSFORMED_KEY_WORDS]) {
    // m_k[0 ~ 3]
    for (int i = 0; i < SQUARE_KEY_BYTES; i++) {
        m_k[i / 4] |= (uint32_t)key[i] << (8 * ((15 - i) % 4));
    }

    // printf("initial round keys:\n");
    // for (int i = 0; i < SQUARE_ROUNDS + 1; i++) {
    //     for (int j = 0; j < 4; j++) {
    //         printf("%08x ", roundkeys(i, j));
    //     }
    //     printf("\n");
    // }
    
    static const uint32_t offset[SQUARE_ROUNDS] = {
	0x01000000UL, 0x02000000UL, 0x04000000UL, 0x08000000UL,
	0x10000000UL, 0x20000000UL, 0x40000000UL, 0x80000000UL,
	};

    for (int i = 1; i <= SQUARE_ROUNDS; i++)
	{
		roundkeys(i, 0) = roundkeys(i-1, 0) ^ rotl(roundkeys(i-1, 3), 8) ^ offset[i-1];
		roundkeys(i, 1) = roundkeys(i-1, 1) ^ roundkeys(i, 0);
		roundkeys(i, 2) = roundkeys(i-1, 2) ^ roundkeys(i, 1);
		roundkeys(i, 3) = roundkeys(i-1, 3) ^ roundkeys(i, 2);
	}

    // printf(" round keys:\n");
    // for (int i = 0; i < SQUARE_ROUNDS + 1; i++) {
    //     for (int j = 0; j < 4; j++) {
    //         printf("%08x ", roundkeys(i, j));
    //     }
    //     printf("\n");
    // }

    for (int i = 0; i < SQUARE_ROUNDS; i++) {
        square_transform(roundkeys4(i), roundkeys4(i));
    }
    // printf("round keys after transform:\n");
    // for (int i = 0; i < SQUARE_ROUNDS + 1; i++) {
    //     for (int j = 0; j < 4; j++) {
    //         printf("%08x ", roundkeys(i, j));
    //     }
    //     printf("\n");
    // }
}