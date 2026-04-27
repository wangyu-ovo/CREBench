#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/sm4.h"

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

    unsigned char key[SM4_KEY_BYTES];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    const unsigned char iv[SM4_BLOCK_BYTES] = {
        0x62, 0x03, 0x73, 0x1c, 0xd2, 0x22, 0x0b, 0x37,
        0xe7, 0xe2, 0xea, 0x9f, 0x12, 0xd6, 0x39, 0xdc
    };

    const unsigned char target_ciphertext[32] = {
        0xe1, 0x4d, 0xa1, 0x4c, 0x71, 0x47, 0x3d, 0xfc,
        0xca, 0x01, 0xd5, 0x40, 0xa8, 0xf6, 0xf8, 0xe4,
        0x8e, 0xe9, 0xa6, 0x78, 0x87, 0x2f, 0x55, 0x89,
        0x37, 0xdf, 0x46, 0xd9, 0xbc, 0xae, 0xad, 0xcd
    };

    unsigned char plaintext[32];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    sm4_ctx ctx;
    sm4_key_expand(&ctx, key);

    unsigned char ciphertext[32];
    sm4_cbc_encrypt(&ctx, iv, plaintext, ciphertext, sizeof(ciphertext));

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 2;
}
