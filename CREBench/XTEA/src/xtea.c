#include "xtea.h"

#ifdef CONSTXOR_XTEA_TABLES
#include "constxor_tables.h"
#define XTEA_MAGIC_TABLE (constxor_xtea_magic())
#else
static const uint32_t xtea_magic[1] = {0x9E3779B9U};
#define XTEA_MAGIC_TABLE (xtea_magic)
#endif

#define XTEA_DELTA_VALUE (XTEA_MAGIC_TABLE[0])

void xtea_enc(const uint8_t in[XTEA_BLOCK_BYTES], uint8_t out[XTEA_BLOCK_BYTES], const uint8_t key[XTEA_KEY_BYTES])
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
    uint32_t sum = 0, delta = XTEA_DELTA_VALUE;
    for (int i = 0; i < XTEA_ROUNDS; i++) {
        v[0] += (((v[1] << 4) ^ (v[1] >> 5)) + v[1]) ^ (sum + k[sum & 3]);
        sum += delta;
        v[1] += (((v[0] << 4) ^ (v[0] >> 5)) + v[0]) ^ (sum + k[(sum>>11) & 3]);
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

void xtea_dec(const uint8_t in[XTEA_BLOCK_BYTES], uint8_t out[XTEA_BLOCK_BYTES], const uint8_t key[XTEA_KEY_BYTES])
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
    uint32_t delta = XTEA_DELTA_VALUE, sum = delta * XTEA_ROUNDS;
    for (int i = 0; i < XTEA_ROUNDS; i++) {
        v[1] -= (((v[0] << 4) ^ (v[0] >> 5)) + v[0]) ^ (sum + k[(sum>>11) & 3]);
        sum -= delta;
        v[0] -= (((v[1] << 4) ^ (v[1] >> 5)) + v[1]) ^ (sum + k[sum & 3]);
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
