/* key_mode=hardcode_plain variant=randomized challenge=3-Way */
/* canonical_flag=5296ba4623d5f79dc7a304be31e852ac3700734b2a67ad686e3a5d098f1c82aa16638a8adb7f115f9059421838708ed5 */
/*
 * 3-Way CTF Challenge
 *
 * This program takes a 48-byte (96 hex characters) input and encrypts it
 * using 3-Way in ECB mode. The goal is to find the plaintext
 * that produces a specific ciphertext.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/threeway.h"

extern void insecure_key_generate(uint8_t *key, size_t key_len);

#define PLAINTEXT_LEN (THREEWAY_BLOCK_SIZE * 4)

static int hex_char_to_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex(const char *hex, uint8_t *out, size_t out_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return 0;
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_char_to_nibble(hex[2 * i]);
        int lo = hex_char_to_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

static void print_hex(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <96-hex-chars>\n", argv[0]);
        return 1;
    }

    /* Target ciphertext (pre-computed from a known plaintext) */
    const uint8_t target_ciphertext[PLAINTEXT_LEN] = {
        0xb9, 0xc7, 0x6c, 0x66, 0x7c, 0xb7, 0x5a, 0x95,
        0x64, 0xef, 0x16, 0x3a, 0x38, 0x13, 0xc2, 0xde,
        0x68, 0xea, 0x26, 0xd7, 0xf0, 0xc1, 0xa3, 0xb0,
        0x6f, 0xbb, 0x7c, 0xd9, 0x67, 0xf4, 0x73, 0x85,
        0x11, 0x19, 0x11, 0x3c, 0x16, 0x3d, 0x1c, 0x76,
        0x87, 0x05, 0x0f, 0xcb, 0xcd, 0xdf, 0xc5, 0x47
    };

    /* Fixed key for the challenge */
    uint8_t key[THREEWAY_KEY_SIZE];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    uint8_t plaintext[PLAINTEXT_LEN];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 96 hex chars (48 bytes).\n");
        return 1;
    }

    threeway_ctx ctx;
    if (threeway_set_encrypt_key(&ctx, key, THREEWAY_ROUNDS) != 0) {
        fprintf(stderr, "Key setup failed.\n");
        return 1;
    }

    uint8_t ciphertext[PLAINTEXT_LEN];
    threeway_ecb_encrypt(&ctx, plaintext, ciphertext, sizeof(ciphertext));

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 1;
}
