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

#define SERPENT_KEY_BYTES 16
#define SERPENT_ROUNDS 32
#define SERPENT_BLOCK_BYTES 16
#define SERPENT_BLOCK_BITS 128
#define SERPENT_TRANSFORMED_KEY_WORDS (4 * (SERPENT_ROUNDS + 1))

#define SERPENT_DELTA 0x9E3779B9 // magic constant, (sqrt 5-1)/2 * 2^32

void serpent_enc(const uint8_t in[SERPENT_BLOCK_BYTES], uint8_t out[SERPENT_BLOCK_BYTES], const uint8_t key[SERPENT_KEY_BYTES]);
// void serpent_dec(const uint8_t in[SERPENT_BLOCK_BYTES], uint8_t out[SERPENT_BLOCK_BYTES], const uint8_t key[SERPENT_KEY_BYTES]);

void serpent_key_schedule(uint32_t *k, unsigned int rounds, const uint8_t *userKey, size_t keylen);

#ifdef __cplusplus
}
#endif