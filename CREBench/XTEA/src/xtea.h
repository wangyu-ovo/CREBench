/*
 * Adapted from Crypto++.
 *
 * Copyright (c) 1995-2024 by Wei Dai. All rights reserved.
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

#define XTEA_KEY_BYTES 16
#define XTEA_ROUNDS 32
#define XTEA_BLOCK_BYTES 8
#define XTEA_BLOCK_BITS 64

#define XTEA_DELTA 0x9E3779B9 // magic constant, (sqrt 5-1)/2 * 2^32

void xtea_enc(const uint8_t in[XTEA_BLOCK_BYTES], uint8_t out[XTEA_BLOCK_BYTES], const uint8_t key[XTEA_KEY_BYTES]);
void xtea_dec(const uint8_t in[XTEA_BLOCK_BYTES], uint8_t out[XTEA_BLOCK_BYTES], const uint8_t key[XTEA_KEY_BYTES]);


#ifdef __cplusplus
}
#endif