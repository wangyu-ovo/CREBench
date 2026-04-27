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

#define LEA_KEY_BYTES 16 // lea supports 128, 192, 256 bit keys, here we use 128 bits
#define LEA_TRANSFORMED_KEY_WORDS 144
#define LEA_ROUNDS 24
#define LEA_BLOCK_BYTES 16
#define LEA_BLOCK_BITS 128

void lea_enc(const uint8_t in[LEA_BLOCK_BYTES], uint8_t out[LEA_BLOCK_BYTES], const uint8_t key[LEA_KEY_BYTES]);
// void lea_dec(const uint8_t in[LEA_BLOCK_BYTES], uint8_t out[LEA_BLOCK_BYTES], const uint8_t key[LEA_KEY_BYTES]);

void lea_key_schedule(uint32_t m_rkeys[LEA_TRANSFORMED_KEY_WORDS], const uint32_t key[LEA_KEY_BYTES / 4]);

#ifdef __cplusplus
}
#endif