#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/rc2.h"

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

    unsigned char key[8];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    const unsigned char iv[RC2_BLOCK_BYTES] = {
        0xaf, 0x55, 0xd4, 0x8b, 0xb3, 0xf4, 0x2f, 0x5b
    };

    const unsigned char target_ciphertext[16] = {
        0x28, 0x89, 0xd2, 0xf8, 0xf7, 0xa5, 0x4b, 0x46,
        0x0f, 0x4b, 0xf6, 0x80, 0x29, 0x6a, 0xdc, 0x3f
    };

    unsigned char plaintext[16];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 32 hex chars (16 bytes).\n");
        return 1;
    }

    rc2_ctx ctx;
    rc2_key_set(&ctx, key, sizeof(key));

    unsigned char ciphertext[16];
    rc2_cbc_encrypt(&ctx, iv, plaintext, ciphertext, sizeof(ciphertext));

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 2;
}
