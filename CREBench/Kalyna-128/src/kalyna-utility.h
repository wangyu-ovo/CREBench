#pragma once

#ifdef __cplusplus
#include <cstddef>     // size_t
#include <cstdint>    // uint8_t, uint32_t
#else
#include <stddef.h>    // size_t
#include <stdint.h>    // uint8_t, uint32_t
#endif


#ifdef __cplusplus
extern "C" {
#endif

typedef uint8_t byte;
typedef uint64_t word64;
extern const word64 T[8][256];  // Columns
extern const word64 IT[8][256]; // Inverse
extern const byte S[4][256];    // Substitution
extern const byte IS[4][256];   // Inverse

void G0128(const word64 x[2], word64 y[2]);
void GL128(const word64 x[2], word64 y[2], const word64 k[2]);
void IMC128(word64 x[2]);
void IG128(const word64 x[2], word64 y[2], const word64 k[2]);
void IGL128(const word64 x[2], word64 y[2], const word64 k[2]);
void G128(const word64 x[2], word64 y[2], const word64 k[2]);
void AddKey(const word64 x[], word64 y[], const word64 k[], int len);
void SubKey(const word64 x[], word64 y[], const word64 k[], int len);
void AddConstant(const word64 x[2], word64 y[2], word64 constant, int len);
void MakeOddKeyLen2(const word64 evenkey[2], word64 oddkey[2]);


#ifdef __cplusplus
}
#endif