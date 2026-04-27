#include "shark.h"

#define W64LIT(x) x##ULL

#ifdef CONSTXOR_SHARK_TABLES
#include "constxor_tables.h"
#define SHARK_CBOX_TABLE ((const uint64_t (*)[256])constxor_shark_cbox())
#else
#define SHARK_CBOX_TABLE (cbox)
#endif

uint64_t byte_reverse64(uint64_t value) {
    uint64_t result = 0;
    for (int i = 0; i < 8; i++) {
        result |= ((value >> (i * 8)) & 0xFF) << ((7 - i) * 8);
    }
    return result;
}
void shark_key_schedule(const uint8_t key[SHARK_KEY_BYTES], uint64_t m_k[SHARK_ROUNDS + 1]) {
    // periodically refill
    for (int i = 0; i < 2; i++) {
        m_k[i] = 0;
        for (int j = 0; j < 8; j++) {
            m_k[i] |= (uint64_t)key[i * 8 + j] << (8 * (7 - j));
        }
    }
    for (int i = 2; i <= SHARK_ROUNDS; i++) {
        m_k[i] = m_k[i - 2];
    }
    // printf("Round keys before transformation:\n");
    // for (int i = 0; i <= SHARK_ROUNDS; i++) {
    //     printf("%llx ", m_k[i]);
    // }
    // printf("\n");
    
    // use cbox[0][...] as round keys to encrypt m_k, to obtain real round keys
    uint64_t temp_keys[SHARK_ROUNDS + 1];
    for (int i = 0; i <= SHARK_ROUNDS; i++) {
        temp_keys[i] = SHARK_CBOX_TABLE[0][i];
        if (i == 0) {
            temp_keys[i] = byte_reverse64(temp_keys[i]);
        } else if (i == SHARK_ROUNDS) {
            temp_keys[i] = byte_reverse64(SHARKTransform(temp_keys[i]));
        }
    }
    shark_enc_with_transformed_key_cbc(m_k, SHARK_ROUNDS + 1, temp_keys, 0ULL);

    for (int i = 1; i <= SHARK_ROUNDS; i++) {
        m_k[i] = byte_reverse64(m_k[i]);
    }
    m_k[SHARK_ROUNDS] = byte_reverse64(SHARKTransform(m_k[SHARK_ROUNDS]));
}
