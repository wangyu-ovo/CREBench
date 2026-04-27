/* key_mode=hardcode_plain variant=randomized challenge=SAFER */
/* canonical_flag=b825a237d7f1f3806df89cd27aa495a76794234d22e8aa860b3a99090cde984c */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/safer.h"

extern void insecure_key_generate(uint8_t *key, size_t key_len);

static int hex_char_to_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex(const char *hex, uint8_t *out, size_t out_len) {
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

static void print_hex(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <64-hex-chars>\n", argv[0]);
        return 1;
    }

    uint8_t key[SAFER_MAX_KEY_SIZE];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    const uint8_t iv[SAFER_BLOCK_SIZE] = {
        0x44, 0x8d, 0x23, 0x0f, 0x9c, 0xb9, 0xc8, 0x73
    };

    const uint8_t target_ciphertext[32] = {
        0xcf, 0xd9, 0x0b, 0xa4, 0x17, 0x91, 0x07, 0x8c,
        0xdd, 0x77, 0xa2, 0x5f, 0x84, 0xf1, 0x0f, 0x9c,
        0xf0, 0x95, 0xec, 0x56, 0xa9, 0xf6, 0x2f, 0x40,
        0xca, 0xbd, 0x99, 0xdf, 0x36, 0xae, 0x3a, 0x01
    };

    uint8_t plaintext[32];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    safer_ctx ctx;
    if (safer_set_key(&ctx, key, sizeof(key)) != 0) {
        fprintf(stderr, "Key setup failed.\n");
        return 1;
    }

    uint8_t ciphertext[32];
    safer_cbc_encrypt(&ctx, iv, plaintext, ciphertext, sizeof(ciphertext));

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 1;
}
