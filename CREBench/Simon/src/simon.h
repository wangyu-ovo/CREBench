/*
 * Adapted for CREBench from the NSA Simon/Speck reference code:
 *   https://github.com/nsacyber/simon-speck
 *
 * Copyright and license attribution:
 *   - Work prepared by U.S. Government employees (17 U.S.C. 105)
 *   - Released under CC0 1.0 Universal (public-domain dedication)
 *   - See upstream LICENSE.md for full legal text
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

#define SIMON_KEY_BYTES 12
#define SIMON_BLOCK_BYTES 8
#define SIMON_BLOCK_BITS 64
// Simon supports multiple modes, here we implement this one

void simon_enc(const uint8_t in[SIMON_BLOCK_BYTES], uint8_t out[SIMON_BLOCK_BYTES], const uint8_t key[SIMON_KEY_BYTES]);
// void simon_dec(const uint8_t in[SIMON_BLOCK_BYTES], uint8_t out[SIMON_BLOCK_BYTES], const uint8_t key[SIMON_KEY_BYTES]);

#ifdef __cplusplus
}
#endif