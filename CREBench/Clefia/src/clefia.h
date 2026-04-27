/*
 * Derived from Sony CLEFIA reference implementation:
 * https://www.sony.co.jp/en/Products/cryptography/clefia/download/data/clefia_ref.c
 *
 * Original reference implementation notice and copyright:
 * Copyright 2007, 2008 Sony Corporation
 *
 * This header declares the 128-bit profile used by this benchmark wrapper.
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

#define CLEFIA_KEY_BYTES 16 // clefia supports 128, 192, 256 bit keys, here we use 128 bits
#define CLEFIA_BLOCK_BYTES 16
#define CLEFIA_BLOCK_BITS 128

void clefia_enc(const uint8_t in[CLEFIA_BLOCK_BYTES], uint8_t out[CLEFIA_BLOCK_BYTES], const uint8_t key[CLEFIA_KEY_BYTES]);
// void clefia_dec(const uint8_t in[CLEFIA_BLOCK_BYTES], uint8_t out[CLEFIA_BLOCK_BYTES], const uint8_t key[CLEFIA_KEY_BYTES]);

#ifdef __cplusplus
}
#endif