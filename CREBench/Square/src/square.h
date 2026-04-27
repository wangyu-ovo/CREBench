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

#define SQUARE_KEY_BYTES 16
#define SQUARE_TRANSFORMED_KEY_WORDS ((SQUARE_ROUNDS + 1) * 4)
#define SQUARE_ROUNDS 8
#define SQUARE_BLOCK_BYTES 16
#define SQUARE_BLOCK_BITS 128

extern const uint8_t Se[256];
extern const uint32_t Te[4][256];

void square_enc(const uint8_t in[SQUARE_BLOCK_BYTES], uint8_t out[SQUARE_BLOCK_BYTES], const uint8_t key[SQUARE_KEY_BYTES]);
// void square_dec(const uint8_t in[SQUARE_BLOCK_BYTES], uint8_t out[SQUARE_BLOCK_BYTES], const uint8_t key[SQUARE_KEY_BYTES]);

// utility fuctions
void square_key_schedule(const uint8_t key[SQUARE_KEY_BYTES], uint32_t m_k[SQUARE_TRANSFORMED_KEY_WORDS]);
void square_transform(uint32_t in[4], uint32_t out[4]);
void squareRound(const uint32_t in[4], uint32_t out[4], const uint32_t T0[256], const uint32_t T1[256], const uint32_t T2[256], const uint32_t T3[256], const uint32_t roundkey[4]);

#ifdef __cplusplus
}
#endif