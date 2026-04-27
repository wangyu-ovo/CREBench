#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/serpent.h"

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

    unsigned char plaintext[SERPENT_BLOCK_BYTES];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 32 hex chars (16 bytes).\n");
        return 1;
    }

    unsigned char key[SERPENT_KEY_BYTES];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    const uint8_t target_ciphertext[SERPENT_BLOCK_BYTES] = {
        0x64, 0xb7, 0x06, 0x12, 0x98, 0x4a, 0xfa, 0x3b,
        0xfd, 0x48, 0x67, 0x76, 0xea, 0xb7, 0xc3, 0xc0
    };

    uint8_t ciphertext[SERPENT_BLOCK_BYTES];
    serpent_enc(plaintext, ciphertext, key);

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    if (memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0) {
        printf("True!");
        return 0;
    }

    printf("False!");
    return 1;
}
