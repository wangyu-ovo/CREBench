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

#define TEA_KEY_BYTES 16
#define TEA_ROUNDS 32
#define TEA_BLOCK_BYTES 8
#define TEA_BLOCK_BITS 64

#define TEA_DELTA 0x9E3779B9 // magic constant, (sqrt 5-1)/2 * 2^32

void tea_enc(const uint8_t in[TEA_BLOCK_BYTES], uint8_t out[TEA_BLOCK_BYTES], const uint8_t key[TEA_KEY_BYTES]);
void tea_dec(const uint8_t in[TEA_BLOCK_BYTES], uint8_t out[TEA_BLOCK_BYTES], const uint8_t key[TEA_KEY_BYTES]);


#ifdef __cplusplus
}
#endif