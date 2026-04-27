#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/chacha20.h"

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
    static const uint8_t nonce[CHACHA20_NONCE_BYTES] = {
        0xb3, 0x1f, 0x2a, 0x2e, 0x56, 0x81, 0x54, 0xe3,
        0xc8, 0x66, 0xb8, 0x50
    };
    static const uint8_t target_ciphertext[32] = {
        0xde, 0xbf, 0x3b, 0x1b, 0xc4, 0x99, 0xbb, 0xb6,
        0x60, 0x14, 0xaf, 0xbe, 0xac, 0x88, 0xe4, 0x92,
        0xc9, 0x0d, 0x24, 0xf5, 0xd4, 0xee, 0xdb, 0xc3,
        0x1b, 0x25, 0x19, 0xc5, 0x78, 0xfc, 0xad, 0x39
    };

    uint8_t key[CHACHA20_KEY_BYTES];
    uint8_t plaintext[32];
    uint8_t ciphertext[32];

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <64-hex-chars>\n", argv[0]);
        return 1;
    }

    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    insecure_key_generate(key, sizeof(key));
    chacha20_crypt(key, nonce, 1U, plaintext, ciphertext, sizeof(ciphertext));

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    if (memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0) {
        puts("Match: True");
        return 0;
    }

    puts("Match: False");
    return 2;
}
