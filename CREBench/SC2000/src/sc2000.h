/*
 * Adapted for CREBench from public SC2000 submission materials.
 *
 * Reference implementation attribution:
 *   - SC2000 submission source (NESSIE mirror):
 *       https://embeddedsw.net/Cipher_Reference_Home.html
 *   - In-source attribution states:
 *       "Implemented by Alexander Myasnikow"
 *       "Web: www.darksoftware.narod.ru"
 *
 * Additional specification reference:
 *   - https://www.ipa.go.jp/en/security/jcmvp/g6ovkg00000065j3-att/09_01espec.pdf
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

#define SC2000_BLOCK_BYTES 16
#define SC2000_KEY_BYTES 32
#define SC2000_ROUNDS 4

void sc2000_enc(const uint8_t in[SC2000_BLOCK_BYTES], uint8_t out[SC2000_BLOCK_BYTES], const uint8_t key[SC2000_KEY_BYTES]);
// void sc2000_dec(const uint8_t in[SC2000_BLOCK_BYTES], uint8_t out[SC2000_BLOCK_BYTES], const uint8_t key[SC2000_KEY_BYTES]);

#ifdef __cplusplus
}
#endif
