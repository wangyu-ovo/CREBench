#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/rc5.h"

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

    uint8_t key[16];
    insecure_key_generate(key, sizeof(key));

    const uint8_t iv[RC5_BLOCK_SIZE] = {
        0x5c, 0xe1, 0xc3, 0xb0, 0x34, 0xd3, 0x21, 0x91
    };

    const uint8_t target_ciphertext[32] = {
        0x25, 0xc3, 0xa3, 0xe6, 0x4e, 0x59, 0x10, 0x31,
        0x0b, 0xd5, 0x16, 0x1f, 0xc4, 0xa6, 0x1b, 0x9d,
        0x36, 0xcd, 0x2a, 0xe2, 0xd1, 0x9c, 0x69, 0x3a,
        0x80, 0x51, 0x13, 0xd9, 0xe3, 0x3a, 0x73, 0x56
    };

    uint8_t plaintext[32];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    rc5_ctx ctx;
    if (rc5_set_key(&ctx, key, sizeof(key), RC5_DEFAULT_ROUNDS) != 0) {
        fprintf(stderr, "Key setup failed.\n");
        return 1;
    }

    uint8_t ciphertext[32];
    rc5_cbc_encrypt(&ctx, iv, plaintext, ciphertext, sizeof(ciphertext));

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 2;
}
