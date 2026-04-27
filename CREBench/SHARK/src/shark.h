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

#define SHARK_KEY_BYTES 16
#define SHARK_ROUNDS 6
#define SHARK_BLOCK_BYTES 8
#define SHARK_BLOCK_BITS 64

extern const uint8_t sbox[256];
extern const uint64_t cbox[8][256];
void shark_enc(const uint8_t in[SHARK_BLOCK_BYTES], uint8_t out[SHARK_BLOCK_BYTES], const uint8_t key[SHARK_KEY_BYTES]);
// void shark_dec(const uint8_t in[SHARK_BLOCK_BYTES], uint8_t out[SHARK_BLOCK_BYTES], const uint8_t key[SHARK_KEY_BYTES]);
void shark_enc_with_transformed_key_cbc(uint64_t *in, int len, const uint64_t m_k[SHARK_ROUNDS], uint64_t iv);
uint64_t shark_enc_with_transformed_key(uint64_t in, const uint64_t m_k[SHARK_ROUNDS]);
uint64_t byte_reverse64(uint64_t value);
uint64_t SHARKTransform(uint64_t a);
void shark_key_schedule(const uint8_t key[SHARK_KEY_BYTES], uint64_t m_k[SHARK_ROUNDS + 1]);

#ifdef __cplusplus
}
#endif