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
        0x4d, 0x52, 0x4d, 0xde, 0xf9, 0x4d, 0x7a, 0xd2,
        0x9e, 0x30, 0xba, 0xc5, 0x1c, 0xea, 0x09, 0x17,
        0x10, 0x7d, 0x76, 0xfb, 0x95, 0x43, 0xd2, 0xf2,
        0x5c, 0x76, 0x9a, 0x72, 0xc4, 0x32, 0xd2, 0x66,
        0x46, 0x8c, 0xd8, 0x15, 0x47, 0xcb, 0xdc, 0x5a,
        0x84, 0x90, 0xff, 0xdc, 0xb7, 0x9f, 0x17, 0x98
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
    return same ? 0 : 2;
}
