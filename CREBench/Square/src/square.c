#include <stdio.h>
#include "square.h"

#ifdef CONSTXOR_SQUARE_TABLES
#include "constxor_tables.h"
#define SQUARE_SE_TABLE (constxor_square_se())
#define SQUARE_TE_TABLE ((const uint32_t (*)[256])constxor_square_te())
#else
#define SQUARE_SE_TABLE (Se)
#define SQUARE_TE_TABLE (Te)
#endif

#define roundkeys(i, j)		m_k[(i)*4+(j)]
#define roundkeys4(i)       (m_k+(i)*4)

void square_enc(const uint8_t in[SQUARE_BLOCK_BYTES], uint8_t out[SQUARE_BLOCK_BYTES], const uint8_t key[SQUARE_KEY_BYTES]) {
    uint32_t m_k[SQUARE_TRANSFORMED_KEY_WORDS] = {0};
    square_key_schedule(key, m_k);

    uint32_t text[4] = {0}, temp[4] = {0};
    // parse input
    for (int i = 0; i < SQUARE_BLOCK_BYTES; i++) {
        text[i / 4] |= (uint32_t)in[i] << (8 * ((15 - i) % 4));
        // printf("%08x %02x\n", text[i / 4], in[i]);
    }
    for (int i = 0; i < 4; i++) {
        // printf("Input word %d: %08x\n", i, text[i]);
    }

    for (int i = 0; i < SQUARE_ROUNDS; i++) {
        if (i == 0) {
            // first round: only add round key
            for (int j = 0; j < 4; j++) {
                text[j] ^= roundkeys(i, j);
            }
        } else {
            squareRound(text, temp, SQUARE_TE_TABLE[0], SQUARE_TE_TABLE[1], SQUARE_TE_TABLE[2], SQUARE_TE_TABLE[3], roundkeys4(i));
            memcpy(text, temp, sizeof(text));
        }
        for (int j = 0; j < 4; j++) {
            // printf("After round %d, word %d: %08x\n", i + 1, j, text[j]);
        }
    }
    // final round
    squareFinal(text, temp, SQUARE_SE_TABLE, roundkeys4(SQUARE_ROUNDS));

    // store results
    for (int i = 0; i < SQUARE_BLOCK_BYTES; i++) {
        out[i] = (temp[i / 4] >> (8 * ((15 - i) % 4))) & 0xFF;
    }
}
