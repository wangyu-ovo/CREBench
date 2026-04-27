#include "tea.h"

#ifdef CONSTXOR_TEA_TABLES
#include "constxor_tables.h"
#define TEA_MAGIC_TABLE (constxor_tea_magic())
#else
static const uint32_t tea_magic[1] = {0x9E3779B9U};
#define TEA_MAGIC_TABLE (tea_magic)
#endif

#define TEA_DELTA_VALUE (TEA_MAGIC_TABLE[0])

void tea_enc(const uint8_t in[TEA_BLOCK_BYTES], uint8_t out[TEA_BLOCK_BYTES], const uint8_t key[TEA_KEY_BYTES])
{
    uint32_t v[2], k[4];

    // Load input block
    v[0] = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | ((uint32_t)in[3]);
    v[1] = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) | ((uint32_t)in[6] << 8) | ((uint32_t)in[7]);

    // Load key
    for (int i = 0; i < 4; i++) {
        k[i] = ((uint32_t)key[i * 4] << 24) | ((uint32_t)key[i * 4 + 1] << 16) |
               ((uint32_t)key[i * 4 + 2] << 8) | ((uint32_t)key[i * 4 + 3]);
    }

    // Encrypt
    uint32_t sum=0, delta=TEA_DELTA_VALUE;
    for (int i=0; i < TEA_ROUNDS; i++) {
        sum += delta;
        v[0] += ((v[1]<<4) + k[0]) ^ (v[1] + sum) ^ ((v[1]>>5) + k[1]);
        v[1] += ((v[0]<<4) + k[2]) ^ (v[0] + sum) ^ ((v[0]>>5) + k[3]);
    }

    // Store output block
    out[0] = (v[0] >> 24) & 0xFF;
    out[1] = (v[0] >> 16) & 0xFF;
    out[2] = (v[0] >> 8) & 0xFF;
    out[3] = v[0] & 0xFF;
    out[4] = (v[1] >> 24) & 0xFF;
    out[5] = (v[1] >> 16) & 0xFF;
    out[6] = (v[1] >> 8) & 0xFF;
    out[7] = v[1] & 0xFF;
}

void tea_dec(const uint8_t in[TEA_BLOCK_BYTES], uint8_t out[TEA_BLOCK_BYTES], const uint8_t key[TEA_KEY_BYTES])
{
    uint32_t v[2], k[4];

    // Load input block
    v[0] = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | ((uint32_t)in[3]);
    v[1] = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) | ((uint32_t)in[6] << 8) | ((uint32_t)in[7]);

    // Load key
    for (int i = 0; i < 4; i++) {
        k[i] = ((uint32_t)key[i * 4] << 24) | ((uint32_t)key[i * 4 + 1] << 16) |
               ((uint32_t)key[i * 4 + 2] << 8) | ((uint32_t)key[i * 4 + 3]);
    }

    // Decrypt
    uint32_t delta=TEA_DELTA_VALUE, sum=delta * TEA_ROUNDS;
    for (int i=0; i < TEA_ROUNDS; i++) {
        v[1] -= ((v[0]<<4) + k[2]) ^ (v[0] + sum) ^ ((v[0]>>5) + k[3]);
        v[0] -= ((v[1]<<4) + k[0]) ^ (v[1] + sum) ^ ((v[1]>>5) + k[1]);
        sum -= delta;
    }

    // Store output block
    out[0] = (v[0] >> 24) & 0xFF;
    out[1] = (v[0] >> 16) & 0xFF;
    out[2] = (v[0] >> 8) & 0xFF;
    out[3] = v[0] & 0xFF;
    out[4] = (v[1] >> 24) & 0xFF;
    out[5] = (v[1] >> 16) & 0xFF;
    out[6] = (v[1] >> 8) & 0xFF;
    out[7] = v[1] & 0xFF;
}
