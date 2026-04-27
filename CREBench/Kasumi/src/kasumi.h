/*
 * KASUMI interface for CREBench.
 *
 * Specification reference:
 *   ETSI TS 135 202 (KASUMI algorithm specification)
 *   https://www.etsi.org/deliver/etsi_ts/135200_135299/135202/07.00.00_60/ts_135202v070000p.pdf
 *
 * License note:
 *   This file provides local interface declarations for an implementation
 *   derived from the public KASUMI specification.
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

#define KASUMI_KEY_BYTES 16 // kasumi supports 128, 192, 256 bit keys, here we use 128 bits
#define KASUMI_BLOCK_BYTES 8
#define KASUMI_BLOCK_BITS 64

void kasumi_enc(const uint8_t in[KASUMI_BLOCK_BYTES], uint8_t out[KASUMI_BLOCK_BYTES], const uint8_t key[KASUMI_KEY_BYTES]);
// void kasumi_dec(const uint8_t in[KASUMI_BLOCK_BYTES], uint8_t out[KASUMI_BLOCK_BYTES], const uint8_t key[KASUMI_KEY_BYTES]);

#ifdef __cplusplus
}
#endif