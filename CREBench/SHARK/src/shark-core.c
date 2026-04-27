#include <stdio.h>
#include "shark.h"

#ifdef CONSTXOR_SHARK_TABLES
#include "constxor_tables.h"
#define SHARK_SBOX_TABLE (constxor_shark_sbox())
#define SHARK_CBOX_TABLE ((const uint64_t (*)[256])constxor_shark_cbox())
#else
#define SHARK_SBOX_TABLE (sbox)
#define SHARK_CBOX_TABLE (cbox)
#endif

uint8_t GetByte(uint64_t word, int index)
{
    return (uint8_t)((word >> (index * 8)) & 0xFF);
}

uint64_t shark_enc_with_transformed_key(uint64_t in, const uint64_t m_k[SHARK_ROUNDS + 1]) {
    // parse input
    uint64_t temp = in;
    // for (int i = 0; i < SHARK_BLOCK_BYTES; i++) {
    //     temp |= (uint64_t)in[i] << (8 * ((7 - i) % 8));
    // }
    // printf("Initial: %llx %llx\n", temp, m_k[0]);
    temp ^= m_k[0]; // round 0
    // printf("After round 0: %llx\n", temp);
    
	temp = SHARK_CBOX_TABLE[0][GetByte(temp, 0)] ^ SHARK_CBOX_TABLE[1][GetByte( temp, 1)]
		^ SHARK_CBOX_TABLE[2][GetByte( temp, 2)] ^ SHARK_CBOX_TABLE[3][GetByte( temp, 3)]
		^ SHARK_CBOX_TABLE[4][GetByte( temp, 4)] ^ SHARK_CBOX_TABLE[5][GetByte( temp, 5)]
		^ SHARK_CBOX_TABLE[6][GetByte( temp, 6)] ^ SHARK_CBOX_TABLE[7][GetByte( temp, 7)]
		^ m_k[1]; // round 1
    // for (int i = 0; i < SHARK_BLOCK_BYTES; i++) {
    //     printf("%02x %llx\n", GetByte(temp, i), cbox[i][GetByte( temp, i)]);
    // }
    // printf("After round 1: %llx\n", temp);

	for(unsigned int i=2; i< SHARK_ROUNDS; i++)
	{
		temp = SHARK_CBOX_TABLE[0][GetByte( temp, 7)] ^ SHARK_CBOX_TABLE[1][GetByte( temp, 6)]
			^ SHARK_CBOX_TABLE[2][GetByte( temp, 5)] ^ SHARK_CBOX_TABLE[3][GetByte( temp, 4)]
			^ SHARK_CBOX_TABLE[4][GetByte( temp, 3)] ^ SHARK_CBOX_TABLE[5][GetByte( temp, 2)]
			^ SHARK_CBOX_TABLE[6][GetByte( temp, 1)] ^ SHARK_CBOX_TABLE[7][GetByte( temp, 0)]
			^ m_k[i];
            // printf("After round %u: %llx\n", i, temp);
	}

    uint64_t result = 0;
    for (int i = 0; i < SHARK_BLOCK_BYTES; i++) {
        // printf("%02x %02x\n", GetByte(temp, i), sbox[GetByte(temp, i)]);
        result |= (uint64_t)SHARK_SBOX_TABLE[GetByte(temp, i)] << (8 * (7 - i));
    }

    // printf("Before final key mixing: %llx\n", result);
    // printf("After final key mixing: %llx\n", result ^ m_k[SHARK_ROUNDS]);
    return result ^ m_k[SHARK_ROUNDS];
    // for (int i = 0; i < SHARK_BLOCK_BYTES; i++) {
    //     out[i] = sbox[GetByte(temp, 7 - i)];
    // }
}

void shark_enc_with_transformed_key_cbc(uint64_t *in, int len, const uint64_t m_k[SHARK_ROUNDS + 1], uint64_t iv) {
    // in-place modification
    // printf("Encrypted with Key: ");
    // for (int i = 0; i <= SHARK_ROUNDS; i++) {
    //     printf("%llx ", m_k[i]);
    // }
    // printf("\n");
    uint64_t prev = iv;
    for (int i = 0; i < len; i++) {
        uint64_t block = prev;
        uint64_t encrypted = shark_enc_with_transformed_key(block, m_k) ^ byte_reverse64(in[i]);
        in[i] = encrypted;
        prev = encrypted;
    }
    // printf("Transformed key schedule:\n");
    // for (int i = 0; i < len; i++) {
    //     printf("%llx ", in[i]);
    // }
    // printf("\n");
}
