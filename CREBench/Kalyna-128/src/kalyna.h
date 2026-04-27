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

#define KALYNA_KEY_BYTES 16 // kalyna supports 128, 256 bit keys, here we use 128 bits
#define KALYNA_ROUNDS 11
#define KALYNA_BLOCK_BYTES 16
#define KALYNA_BLOCK_BITS 128

void kalyna_enc(const uint8_t in[KALYNA_BLOCK_BYTES], uint8_t out[KALYNA_BLOCK_BYTES], const uint8_t key[KALYNA_KEY_BYTES]);
// void kalyna_dec(const uint8_t in[KALYNA_BLOCK_BYTES], uint8_t out[KALYNA_BLOCK_BYTES], const uint8_t key[KALYNA_KEY_BYTES]);

void kalyna_key_schedule(uint64_t m_rkeys[KALYNA_ROUNDS * 2], const uint8_t byte_key[KALYNA_KEY_BYTES]);

#ifdef __cplusplus
}
#endif