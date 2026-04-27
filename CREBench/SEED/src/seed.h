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

#define SEED_KEY_BYTES 16
#define SEED_ROUNDS 16
#define SEED_BLOCK_BYTES 16
#define SEED_BLOCK_BITS 128

void seed_enc(const uint8_t in[SEED_BLOCK_BYTES], uint8_t out[SEED_BLOCK_BYTES], const uint8_t key[SEED_KEY_BYTES]);
// void seed_dec(const uint8_t in[SEED_BLOCK_BYTES], uint8_t out[SEED_BLOCK_BYTES], const uint8_t key[SEED_KEY_BYTES]);

#ifdef __cplusplus
}
#endif