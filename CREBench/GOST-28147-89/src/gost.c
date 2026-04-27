/*
 * Adapted from Crypto++.
 *
 * Copyright (c) 1995-2024 by Wei Dai. All rights reserved.
 */

#include <stdio.h>

#include "gost.h"

extern uint32_t sTable[4][256];
extern void precalculateSTable();

uint32_t f(uint32_t x)
{
    return sTable[3][(x >> 24) & 0xFF] ^ sTable[2][(x >> 16) & 0xFF]
         ^ sTable[1][(x >> 8) & 0xFF] ^ sTable[0][x & 0xFF];
}

void gost_enc(const uint8_t in[GOST_BLOCK_BYTES], uint8_t out[GOST_BLOCK_BYTES], const uint8_t key[GOST_KEY_BYTES])
{
    precalculateSTable();
	uint32_t n1, n2, t;
    n1 = ((uint32_t)in[3] << 24) | ((uint32_t)in[2] << 16) | ((uint32_t)in[1] << 8) | (uint32_t)in[0];
    n2 = ((uint32_t)in[7] << 24) | ((uint32_t)in[6] << 16) | ((uint32_t)in[5] << 8) | (uint32_t)in[4];

    const uint32_t* m_key = (const uint32_t*)key;

    // printf("Initial: n1=%x, n2=%x\n", n1, n2);
	for (unsigned int i=0; i<3; i++)
	{
		n2 ^= f(n1+m_key[0]);
		n1 ^= f(n2+m_key[1]);
		n2 ^= f(n1+m_key[2]);
		n1 ^= f(n2+m_key[3]);
		n2 ^= f(n1+m_key[4]);
		n1 ^= f(n2+m_key[5]);
		n2 ^= f(n1+m_key[6]);
		n1 ^= f(n2+m_key[7]);
        // printf("After round %d: n1=%x, n2=%x\n", i+1, n1, n2);
	}

	n2 ^= f(n1+m_key[7]);
	n1 ^= f(n2+m_key[6]);
	n2 ^= f(n1+m_key[5]);
	n1 ^= f(n2+m_key[4]);
	n2 ^= f(n1+m_key[3]);
	n1 ^= f(n2+m_key[2]);
	n2 ^= f(n1+m_key[1]);
	n1 ^= f(n2+m_key[0]);
    // printf("After final transformation: n1=%x, n2=%x\n", n1, n2);

    out[3] = (n2 >> 24) & 0xFF;
    out[2] = (n2 >> 16) & 0xFF;
    out[1] = (n2 >> 8) & 0xFF;
    out[0] = n2 & 0xFF;
    out[7] = (n1 >> 24) & 0xFF;
    out[6] = (n1 >> 16) & 0xFF;
    out[5] = (n1 >> 8) & 0xFF;
    out[4] = n1 & 0xFF;
}
// void gost_dec(const uint8_t in[GOST_BLOCK_BYTES], uint8_t out[GOST_BLOCK_BYTES], const uint8_t key[GOST_KEY_BYTES])
// {
//     precalculateSTable();
//     uint32_t n1, n2, t;
//     n1 = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
//     n2 = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) | ((uint32_t)in[6] << 8) | (uint32_t)in[7];

//     const uint32_t* m_key = (const uint32_t*)key;

//     n2 ^= f(n1+m_key[0]);
//     n1 ^= f(n2+m_key[1]);
//     n2 ^= f(n1+m_key[2]);
//     n1 ^= f(n2+m_key[3]);
//     n2 ^= f(n1+m_key[4]);
//     n1 ^= f(n2+m_key[5]);
//     n2 ^= f(n1+m_key[6]);
//     n1 ^= f(n2+m_key[7]);

//     for (unsigned int i=0; i<3; i++)
//     {
//         n2 ^= f(n1+m_key[7]);
//         n1 ^= f(n2+m_key[6]);
//         n2 ^= f(n1+m_key[5]);
//         n1 ^= f(n2+m_key[4]);
//         n2 ^= f(n1+m_key[3]);
//         n1 ^= f(n2+m_key[2]);
//         n2 ^= f(n1+m_key[1]);
//         n1 ^= f(n2+m_key[0]);
//     }

//     out[0] = (n2 >> 24) & 0xFF;
//     out[1] = (n2 >> 16) & 0xFF;
//     out[2] = (n2 >> 8) & 0xFF;
//     out[3] = n2 & 0xFF;
//     out[4] = (n1 >> 24) & 0xFF;
//     out[5] = (n1 >> 16) & 0xFF;
//     out[6] = (n1 >> 8) & 0xFF;
//     out[7] = n1 & 0xFF;
// }