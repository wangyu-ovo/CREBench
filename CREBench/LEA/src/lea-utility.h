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
typedef uint32_t word32;
typedef uint64_t word64;
extern const word32 delta[8][36];

word32 rotlConstant(word32 value, int shift);
word32 rotrConstant(word32 value, int shift);

#ifdef __cplusplus
}
#endif