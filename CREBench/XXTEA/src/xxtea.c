#include "xxtea.h"
#include <string.h>

#ifdef CONSTXOR_XXTEA_TABLES
#include "constxor_tables.h"
#define XXTEA_MAGIC_TABLE (constxor_xxtea_magic())
#else
static const uint32_t xxtea_magic[1] = {0x9E3779B9U};
#define XXTEA_MAGIC_TABLE (xxtea_magic)
#endif

#define XXTEA_DELTA_VALUE (XXTEA_MAGIC_TABLE[0])

#define MX (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z))


void xxtea_uint_encrypt(const uint32_t * in, size_t len, uint32_t * key, uint32_t * out) {
    memcpy(out, in, len * 4);
    uint32_t n = (uint32_t)len - 1;
    uint32_t z = out[n], y, p, q = 6 + 52 / (n + 1), sum = 0, e;

    if (n < 1) return;

    while (0 < q--) {
        sum += XXTEA_DELTA_VALUE;
        e = sum >> 2 & 3;

        for (p = 0; p < n; p++) {
            y = out[p + 1];
            z = out[p] += MX;
        }

        y = out[0];
        z = out[n] += MX;
    }
}

void xxtea_enc(const uint8_t in[XXTEA_BLOCK_BYTES], uint8_t out[XXTEA_BLOCK_BYTES], const uint8_t key[XXTEA_KEY_BYTES]) {
    uint32_t in_uint32[XXTEA_BLOCK_BYTES / 4] = {0};
    uint32_t out_uint32[XXTEA_BLOCK_BYTES / 4] = {0};
    uint32_t key_uint32[XXTEA_KEY_BYTES / 4] = {0};

    for (int i = 0; i < XXTEA_BLOCK_BYTES / 4; i++) {
        in_uint32[i] = ((uint32_t)in[i * 4]) | ((uint32_t)in[i * 4 + 1] << 8) | ((uint32_t)in[i * 4 + 2] << 16) | ((uint32_t)in[i * 4 + 3] << 24);
    }

    for (int i = 0; i < XXTEA_KEY_BYTES / 4; i++) {
        key_uint32[i] = ((uint32_t)key[i * 4]) | ((uint32_t)key[i * 4 + 1] << 8) | ((uint32_t)key[i * 4 + 2] << 16) | ((uint32_t)key[i * 4 + 3] << 24);
    }

    xxtea_uint_encrypt(in_uint32, XXTEA_BLOCK_BYTES / 4, key_uint32, out_uint32);

    for (int i = 0; i < XXTEA_BLOCK_BYTES / 4; i++) {
        out[i * 4] = (uint8_t)(out_uint32[i] & 0xFF);
        out[i * 4 + 1] = (uint8_t)((out_uint32[i] >> 8) & 0xFF);
        out[i * 4 + 2] = (uint8_t)((out_uint32[i] >> 16) & 0xFF);
        out[i * 4 + 3] = (uint8_t)((out_uint32[i] >> 24) & 0xFF);
    }
}
