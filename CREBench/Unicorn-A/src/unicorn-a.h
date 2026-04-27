/*
 * Adapted for CREBench from CIPHERUNICORN-A reference materials.
 *
 * Reference source:
 *   https://embeddedsw.net/Cipher_Reference_Home.html
 *
 * Copyright and attribution:
 *   CIPHERUNICORN-A was designed and published by NEC Corporation.
 *   Original specification/reference materials remain under their
 *   respective copyright.
 */
 
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

typedef uint8_t u8;
typedef uint32_t u32;
typedef int32_t s32;


#define UNICORN_BLOCK_BYTES 16
#define UNICORN_KEY_BYTES 32 // unicorn-a uses 128, 192 or 256-bit key, here we use 256-bit key

void unicorn_enc(const u8 in[UNICORN_BLOCK_BYTES], u8 out[UNICORN_BLOCK_BYTES], const u8 key[UNICORN_KEY_BYTES]);

#ifdef __cplusplus
}
#endif