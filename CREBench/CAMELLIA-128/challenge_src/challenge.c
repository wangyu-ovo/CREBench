#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/camellia.h"

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
        fprintf(stderr, "Usage: %s <32-hex-chars>\n", argv[0]);
        return 1;
    }

    unsigned char plaintext[16];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 32 hex chars (16 bytes).\n");
        return 1;
    }

    unsigned char key[16];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    const uint8_t target_ciphertext[16] = {
        0x51, 0xeb, 0x46, 0xae, 0x7d, 0x06, 0xdf, 0xd3,
        0x78, 0xa7, 0xb7, 0x5f, 0xb1, 0x3e, 0x03, 0xfa
    };

    CamelliaData ctx;
    uint8_t ciphertext[16];

    if (camelliaKeysche(Camellia128Encrypt, key, &ctx) < 0) {
        return 1;
    }

    memset(ciphertext, 0, sizeof(ciphertext));
    if (camelliaDatarand(plaintext, &ctx, ciphertext) < 0) {
        return 1;
    }

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    if (memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0) {
        printf("True!");
        return 0;
    }

    printf("False");
    return 1;
}
