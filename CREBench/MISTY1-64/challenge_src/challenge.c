#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/misty1.h"

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
        fprintf(stderr, "Usage: %s <128-hex-chars>\n", argv[0]);
        return 1;
    }

    uint8_t key[MISTY1_KEY_SIZE];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    const uint8_t target_ciphertext[64] = {
        0xb2, 0xcf, 0x33, 0x23, 0x05, 0x0b, 0x88, 0x98,
        0x7c, 0x87, 0x03, 0x35, 0x6f, 0xe2, 0x5e, 0x4d,
        0x4e, 0xa1, 0x37, 0x74, 0x75, 0xbf, 0x76, 0x53,
        0x2f, 0xd5, 0x2e, 0xda, 0x6b, 0x3e, 0x18, 0xd9,
        0x3c, 0xcc, 0x2c, 0x8a, 0xef, 0x87, 0x8a, 0x63,
        0xf5, 0x35, 0x75, 0xec, 0x51, 0xcc, 0x1b, 0x66,
        0xfc, 0x43, 0xf4, 0xc1, 0xec, 0x2c, 0xc4, 0x79,
        0x31, 0x86, 0x28, 0x9b, 0x0e, 0x6d, 0xfe, 0x64
    };

    uint8_t plaintext[64];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 128 hex chars (64 bytes).\n");
        return 1;
    }

    misty1_ctx ctx;
    if (misty1_set_key(&ctx, key) != 0) {
        fprintf(stderr, "Key setup failed.\n");
        return 1;
    }

    uint8_t ciphertext[64];
    misty1_ecb_encrypt(&ctx, plaintext, ciphertext, sizeof(ciphertext));

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 2;
}
