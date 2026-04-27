/*
 * Adapted from Crypto++
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

#define IDEA_KEY_BYTES 16
#define IDEA_TRANSFORMED_KEY_WORDS 52
#define IDEA_ROUNDS 8
#define IDEA_BLOCK_BYTES 8
#define IDEA_BLOCK_BITS 64

void idea_enc(const uint8_t in[IDEA_BLOCK_BYTES], uint8_t out[IDEA_BLOCK_BYTES], const uint8_t key[IDEA_KEY_BYTES]);
// void idea_dec(const uint8_t in[IDEA_BLOCK_BYTES], uint8_t out[IDEA_BLOCK_BYTES], const uint8_t key[IDEA_KEY_BYTES]);

#ifdef __cplusplus
}
#endif