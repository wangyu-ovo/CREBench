/*
 * Adapted for CREBench from public Threefish implementations.
 *
 * Main reference attributions:
 *   - Crypto++ (threefish.cpp):
 *       written and placed in the public domain by Jeffrey Walton
 *       based on public-domain code by Keru Kuro
 *   - Botan (threefish_512.cpp):
 *       Copyright (C) 2013, 2014, 2016 Jack Lloyd
 *       Botan is released under the Simplified BSD License
 *   - RustCrypto (block-ciphers/threefish):
 *       Copyright (c) The Rust-Crypto Project Developers
 *       License: MIT OR Apache-2.0
 *
 * Threefish-512 Block Cipher (CBC mode)
 *
 * Block size: 512 bits (64 bytes)
 * Key size:   512 bits (64 bytes)
 * Tweak size: 128 bits (16 bytes)
 */
#ifndef THREEFISH_H
#define THREEFISH_H

#include <stddef.h>
#include <stdint.h>

#define THREEFISH_512_BLOCK_SIZE 64
#define THREEFISH_512_KEY_SIZE 64
#define THREEFISH_TWEAK_SIZE 16

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t key_words[8];
    uint64_t tweak_words[2];
    uint64_t subkeys[19][8];
} threefish512_ctx;

int threefish512_set_key(threefish512_ctx *ctx, const uint8_t *key, size_t key_len);
int threefish512_set_tweak(threefish512_ctx *ctx, const uint8_t *tweak, size_t tweak_len);

void threefish512_encrypt_block(const threefish512_ctx *ctx, const uint8_t *in, uint8_t *out);
void threefish512_decrypt_block(const threefish512_ctx *ctx, const uint8_t *in, uint8_t *out);

void threefish512_cbc_encrypt(const threefish512_ctx *ctx,
                              const uint8_t *iv,
                              const uint8_t *in,
                              uint8_t *out,
                              size_t len);

void threefish512_cbc_decrypt(const threefish512_ctx *ctx,
                              const uint8_t *iv,
                              const uint8_t *in,
                              uint8_t *out,
                              size_t len);

#ifdef __cplusplus
}
#endif

#endif /* THREEFISH_H */
