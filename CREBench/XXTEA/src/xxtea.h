/*
 * Adapted for CREBench from xxtea-c.
 *
 * Copyright (c) 2008-2016 Ma Bingyao (mabingyao@gmail.com)
 * License: MIT
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

#define XXTEA_KEY_BYTES 16
#define XXTEA_BLOCK_BYTES 16
#define XXTEA_BLOCK_BITS 128
#define XXTEA_DELTA 0x9e3779b9


void xxtea_enc(const uint8_t in[XXTEA_BLOCK_BYTES], uint8_t out[XXTEA_BLOCK_BYTES], const uint8_t key[XXTEA_KEY_BYTES]);
// void xxtea_dec(const uint8_t in[XXTEA_BLOCK_BYTES], uint8_t out[XXTEA_BLOCK_BYTES], const uint8_t key[XXTEA_KEY_BYTES]);

#ifdef __cplusplus
}
#endif