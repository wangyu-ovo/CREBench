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

#define GOST_KEY_BYTES 32
#define GOST_ROUNDS 32
#define GOST_BLOCK_BYTES 8
#define GOST_BLOCK_BITS 64

void gost_enc(const uint8_t in[GOST_BLOCK_BYTES], uint8_t out[GOST_BLOCK_BYTES], const uint8_t key[GOST_KEY_BYTES]);
// void gost_dec(const uint8_t in[GOST_BLOCK_BYTES], uint8_t out[GOST_BLOCK_BYTES], const uint8_t key[GOST_KEY_BYTES]);

#ifdef __cplusplus
}
#endif