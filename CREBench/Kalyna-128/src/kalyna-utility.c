#include "kalyna.h"
#include "kalyna-utility.h"

#ifdef CONSTXOR_KALYNA_TABLES
#include "constxor_tables.h"
#define KALYNA_T_TABLE ((const word64 (*)[256])constxor_kalyna_t())
#define KALYNA_IT_TABLE ((const word64 (*)[256])constxor_kalyna_it())
#define KALYNA_S_TABLE ((const byte (*)[256])constxor_kalyna_s())
#define KALYNA_IS_TABLE ((const byte (*)[256])constxor_kalyna_is())
#else
#define KALYNA_T_TABLE (T)
#define KALYNA_IT_TABLE (IT)
#define KALYNA_S_TABLE (S)
#define KALYNA_IS_TABLE (IS)
#endif


void G0128(const word64 x[2], word64 y[2])
{
    y[0] = KALYNA_T_TABLE[0][(byte)x[0]] ^ KALYNA_T_TABLE[1][(byte)(x[0] >> 8)] ^ KALYNA_T_TABLE[2][(byte)(x[0] >> 16)] ^ KALYNA_T_TABLE[3][(byte)(x[0] >> 24)] ^
        KALYNA_T_TABLE[4][(byte)(x[1] >> 32)] ^ KALYNA_T_TABLE[5][(byte)(x[1] >> 40)] ^ KALYNA_T_TABLE[6][(byte)(x[1] >> 48)] ^ KALYNA_T_TABLE[7][(byte)(x[1] >> 56)];
    y[1] = KALYNA_T_TABLE[0][(byte)x[1]] ^ KALYNA_T_TABLE[1][(byte)(x[1] >> 8)] ^ KALYNA_T_TABLE[2][(byte)(x[1] >> 16)] ^ KALYNA_T_TABLE[3][(byte)(x[1] >> 24)] ^
        KALYNA_T_TABLE[4][(byte)(x[0] >> 32)] ^ KALYNA_T_TABLE[5][(byte)(x[0] >> 40)] ^ KALYNA_T_TABLE[6][(byte)(x[0] >> 48)] ^ KALYNA_T_TABLE[7][(byte)(x[0] >> 56)];
}

void GL128(const word64 x[2], word64 y[2], const word64 k[2])
{
    y[0] = k[0] + (KALYNA_T_TABLE[0][(byte)x[0]] ^ KALYNA_T_TABLE[1][(byte)(x[0] >> 8)] ^ KALYNA_T_TABLE[2][(byte)(x[0] >> 16)] ^ KALYNA_T_TABLE[3][(byte)(x[0] >> 24)] ^
        KALYNA_T_TABLE[4][(byte)(x[1] >> 32)] ^ KALYNA_T_TABLE[5][(byte)(x[1] >> 40)] ^ KALYNA_T_TABLE[6][(byte)(x[1] >> 48)] ^ KALYNA_T_TABLE[7][(byte)(x[1] >> 56)]);
    y[1] = k[1] + (KALYNA_T_TABLE[0][(byte)x[1]] ^ KALYNA_T_TABLE[1][(byte)(x[1] >> 8)] ^ KALYNA_T_TABLE[2][(byte)(x[1] >> 16)] ^ KALYNA_T_TABLE[3][(byte)(x[1] >> 24)] ^
        KALYNA_T_TABLE[4][(byte)(x[0] >> 32)] ^ KALYNA_T_TABLE[5][(byte)(x[0] >> 40)] ^ KALYNA_T_TABLE[6][(byte)(x[0] >> 48)] ^ KALYNA_T_TABLE[7][(byte)(x[0] >> 56)]);
}

void IMC128(word64 x[2])
{
    x[0] = KALYNA_IT_TABLE[0][KALYNA_S_TABLE[0][(byte)x[0]]] ^ KALYNA_IT_TABLE[1][KALYNA_S_TABLE[1][(byte)(x[0] >> 8)]] ^ KALYNA_IT_TABLE[2][KALYNA_S_TABLE[2][(byte)(x[0] >> 16)]] ^ KALYNA_IT_TABLE[3][KALYNA_S_TABLE[3][(byte)(x[0] >> 24)]] ^
        KALYNA_IT_TABLE[4][KALYNA_S_TABLE[0][(byte)(x[0] >> 32)]] ^ KALYNA_IT_TABLE[5][KALYNA_S_TABLE[1][(byte)(x[0] >> 40)]] ^ KALYNA_IT_TABLE[6][KALYNA_S_TABLE[2][(byte)(x[0] >> 48)]] ^ KALYNA_IT_TABLE[7][KALYNA_S_TABLE[3][(byte)(x[0] >> 56)]];
    x[1] = KALYNA_IT_TABLE[0][KALYNA_S_TABLE[0][(byte)x[1]]] ^ KALYNA_IT_TABLE[1][KALYNA_S_TABLE[1][(byte)(x[1] >> 8)]] ^ KALYNA_IT_TABLE[2][KALYNA_S_TABLE[2][(byte)(x[1] >> 16)]] ^ KALYNA_IT_TABLE[3][KALYNA_S_TABLE[3][(byte)(x[1] >> 24)]] ^
        KALYNA_IT_TABLE[4][KALYNA_S_TABLE[0][(byte)(x[1] >> 32)]] ^ KALYNA_IT_TABLE[5][KALYNA_S_TABLE[1][(byte)(x[1] >> 40)]] ^ KALYNA_IT_TABLE[6][KALYNA_S_TABLE[2][(byte)(x[1] >> 48)]] ^ KALYNA_IT_TABLE[7][KALYNA_S_TABLE[3][(byte)(x[1] >> 56)]];
}

void IG128(const word64 x[2], word64 y[2], const word64 k[2])
{
    y[0] = k[0] ^ KALYNA_IT_TABLE[0][(byte)x[0]] ^ KALYNA_IT_TABLE[1][(byte)(x[0] >> 8)] ^ KALYNA_IT_TABLE[2][(byte)(x[0] >> 16)] ^ KALYNA_IT_TABLE[3][(byte)(x[0] >> 24)] ^
        KALYNA_IT_TABLE[4][(byte)(x[1] >> 32)] ^ KALYNA_IT_TABLE[5][(byte)(x[1] >> 40)] ^ KALYNA_IT_TABLE[6][(byte)(x[1] >> 48)] ^ KALYNA_IT_TABLE[7][(byte)(x[1] >> 56)];
    y[1] = k[1] ^ KALYNA_IT_TABLE[0][(byte)x[1]] ^ KALYNA_IT_TABLE[1][(byte)(x[1] >> 8)] ^ KALYNA_IT_TABLE[2][(byte)(x[1] >> 16)] ^ KALYNA_IT_TABLE[3][(byte)(x[1] >> 24)] ^
        KALYNA_IT_TABLE[4][(byte)(x[0] >> 32)] ^ KALYNA_IT_TABLE[5][(byte)(x[0] >> 40)] ^ KALYNA_IT_TABLE[6][(byte)(x[0] >> 48)] ^ KALYNA_IT_TABLE[7][(byte)(x[0] >> 56)];
}

void IGL128(const word64 x[2], word64 y[2], const word64 k[2])
{
    y[0] = ((word64)(KALYNA_IS_TABLE[0][(byte)x[0]]) ^ (word64)(KALYNA_IS_TABLE[1][(byte)(x[0] >> 8)]) << 8 ^ (word64)(KALYNA_IS_TABLE[2][(byte)(x[0] >> 16)]) << 16 ^ (word64)(KALYNA_IS_TABLE[3][(byte)(x[0] >> 24)]) << 24 ^
        (word64)(KALYNA_IS_TABLE[0][(byte)(x[1] >> 32)]) << 32 ^ (word64)(KALYNA_IS_TABLE[1][(byte)(x[1] >> 40)]) << 40 ^ (word64)(KALYNA_IS_TABLE[2][(byte)(x[1] >> 48)]) << 48 ^ (word64)(KALYNA_IS_TABLE[3][(byte)(x[1] >> 56)]) << 56) - k[0];
    y[1] = ((word64)(KALYNA_IS_TABLE[0][(byte)x[1]]) ^ (word64)(KALYNA_IS_TABLE[1][(byte)(x[1] >> 8)]) << 8 ^ (word64)(KALYNA_IS_TABLE[2][(byte)(x[1] >> 16)]) << 16 ^ (word64)(KALYNA_IS_TABLE[3][(byte)(x[1] >> 24)]) << 24 ^
        (word64)(KALYNA_IS_TABLE[0][(byte)(x[0] >> 32)]) << 32 ^ (word64)(KALYNA_IS_TABLE[1][(byte)(x[0] >> 40)]) << 40 ^ (word64)(KALYNA_IS_TABLE[2][(byte)(x[0] >> 48)]) << 48 ^ (word64)(KALYNA_IS_TABLE[3][(byte)(x[0] >> 56)]) << 56) - k[1];
}


void G128(const word64 x[2], word64 y[2], const word64 k[2])
{
    y[0] = k[0] ^ KALYNA_T_TABLE[0][(byte)x[0]] ^ KALYNA_T_TABLE[1][(byte)(x[0] >> 8)] ^ KALYNA_T_TABLE[2][(byte)(x[0] >> 16)] ^ KALYNA_T_TABLE[3][(byte)(x[0] >> 24)] ^
        KALYNA_T_TABLE[4][(byte)(x[1] >> 32)] ^ KALYNA_T_TABLE[5][(byte)(x[1] >> 40)] ^ KALYNA_T_TABLE[6][(byte)(x[1] >> 48)] ^ KALYNA_T_TABLE[7][(byte)(x[1] >> 56)];
    y[1] = k[1] ^ KALYNA_T_TABLE[0][(byte)x[1]] ^ KALYNA_T_TABLE[1][(byte)(x[1] >> 8)] ^ KALYNA_T_TABLE[2][(byte)(x[1] >> 16)] ^ KALYNA_T_TABLE[3][(byte)(x[1] >> 24)] ^
        KALYNA_T_TABLE[4][(byte)(x[0] >> 32)] ^ KALYNA_T_TABLE[5][(byte)(x[0] >> 40)] ^ KALYNA_T_TABLE[6][(byte)(x[0] >> 48)] ^ KALYNA_T_TABLE[7][(byte)(x[0] >> 56)];
}

void AddKey(const word64 x[], word64 y[], const word64 k[], int len) {
    for (int i = 0; i < len; i++) {
        y[i] = x[i] + k[i];
    }
}

void SubKey(const word64 x[], word64 y[], const word64 k[], int len) {
    for (int i = 0; i < len; i++) {
        y[i] = x[i] - k[i];
    }
}

void MakeOddKeyLen2(const word64 evenkey[], word64 oddkey[]) {
    oddkey[0] = (evenkey[1] << 8) | (evenkey[0] >> 56);
    oddkey[1] = (evenkey[0] << 8) | (evenkey[1] >> 56);
}

void AddConstant(const word64 x[], word64 y[], word64 constant, int len) {
    for (int i = 0; i < len; i++) {
        y[i] = x[i] + constant;
    }
}
