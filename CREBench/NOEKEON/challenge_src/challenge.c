#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/noekeon.h"

extern void insecure_key_generate(uint8_t *key, size_t key_len);

static int hex_char_to_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex(const char *hex, unsigned char *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return 0;
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_char_to_nibble(hex[2 * i]);
        int lo = hex_char_to_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
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

    unsigned char key[NOEKEON_KEY_SIZE];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    const unsigned char iv[NOEKEON_BLOCK_SIZE] = {
        0xf1, 0xf5, 0x79, 0x64, 0x9e, 0x51, 0x6e, 0xea,
        0xca, 0x29, 0x88, 0xe3, 0x6a, 0xac, 0xf0, 0x2f
    };

    const unsigned char target_ciphertext[32] = {
        0xd7, 0xfb, 0xab, 0x98, 0x38, 0x9c, 0x59, 0xd3,
        0xcb, 0x60, 0x4c, 0x10, 0x24, 0x84, 0x3e, 0x22,
        0xf7, 0xa9, 0xfc, 0xcc, 0x9e, 0x9f, 0xf4, 0x4c,
        0x49, 0xa7, 0xb2, 0x10, 0xa1, 0x1a, 0x50, 0xc1
    };

    unsigned char plaintext[32];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    noekeon_ctx ctx;
    if (noekeon_set_key(&ctx, key, sizeof(key)) != 0) {
        fprintf(stderr, "Key setup failed.\n");
        return 1;
    }

    unsigned char ciphertext[32];
    noekeon_cbc_encrypt(&ctx, iv, plaintext, ciphertext, sizeof(ciphertext));

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 2;
}
