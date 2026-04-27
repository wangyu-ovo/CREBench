/* key_mode=weak_prng_seeded variant=randomized challenge=3-Way */
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
        0x75, 0xa6, 0x10, 0xd4, 0x4b, 0x0b, 0xbb, 0x6e,
        0x2a, 0xb8, 0x50, 0x13, 0x0a, 0x87, 0xdc, 0x78,
        0x95, 0xa5, 0x1c, 0x7e, 0x33, 0x67, 0x51, 0x32,
        0xc0, 0xf5, 0x81, 0x4d, 0xeb, 0x63, 0x69, 0x90,
        0x79, 0x26, 0x57, 0xce, 0x25, 0x02, 0x7c, 0x20,
        0x06, 0x0a, 0xcc, 0x8f, 0xb3, 0x28, 0xb9, 0x09
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
