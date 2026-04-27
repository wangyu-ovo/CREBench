/*
 * Adapted from Crypto++.
 *
 * Copyright (c) 1995-2024 by Wei Dai. All rights reserved.
 */

#include <stdio.h>
#include <stdbool.h>
#include "gost.h"

#ifdef CONSTXOR_GOST_TABLES
#include "constxor_tables.h"
#define GOST_SBOX_TABLE ((const uint8_t (*)[16])constxor_gost_sbox())
#else
// these are the S-boxes given in Applied Cryptography 2nd Ed., p. 333
const uint8_t sBox[8][16]={
	{4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3},
	{14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9},
	{5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11},
	{7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3},
	{6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2},
	{4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14},
	{13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12},
	{1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12}};
#define GOST_SBOX_TABLE (sBox)
#endif

uint32_t sTable[4][256];

uint32_t rotlMod(uint32_t value, unsigned int shift)
{
	return (value << shift) | (value >> (32 - shift));
}

void precalculateSTable()
{
    static volatile bool sTableCalculated = false;
	if (!sTableCalculated)
	{
		for (unsigned i = 0; i < 4; i++) {
			for (unsigned j = 0; j < 256; j++)
			{
				uint32_t temp = GOST_SBOX_TABLE[2*i][j%16] | (GOST_SBOX_TABLE[2*i+1][j/16] << 4);
				sTable[i][j] = rotlMod(temp, 11+8*i);
				// printf("%08x, ", sTable[i][j]);
			}
			// puts("");
		}
		sTableCalculated=true;
	}
}

