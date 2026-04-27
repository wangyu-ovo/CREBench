#include <stdio.h>
#include "shark.h"

void shark_enc(const uint8_t in[SHARK_BLOCK_BYTES], uint8_t out[SHARK_BLOCK_BYTES], const uint8_t key[SHARK_KEY_BYTES]) {
    uint64_t m_k[SHARK_ROUNDS + 1] = {0};
    shark_key_schedule(key, m_k);
    // printf("Transformed round keys:\n");
    // for (int i = 0; i < SHARK_ROUNDS + 1; i++) {
    //     printf("%llx ", m_k[i]);
    // }
    // printf("\n");
    uint64_t input = 0;
    // parse input
    for (int i = 0; i < SHARK_BLOCK_BYTES; i++) {
        input |= (uint64_t)in[i] << (8 * i);
    }
    uint64_t encrypted = shark_enc_with_transformed_key(input, m_k);
    // printf("Final encrypted value: %llx\n", encrypted);
    // store output
    for (int i = 0; i < SHARK_BLOCK_BYTES; i++) {
        out[i] = (encrypted >> (8 * i)) & 0xFF;
    }
}