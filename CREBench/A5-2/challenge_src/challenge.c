#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../src/a5_2.h"

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
    for (size_t i = 0; i < out_len; ++i) {
        int hi = hex_char_to_nibble(hex[2 * i]);
        int lo = hex_char_to_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

static uint32_t load_be32(const uint8_t in[4]) {
    return ((uint32_t)in[0] << 24) |
           ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) |
           (uint32_t)in[3];
}

static void print_hex(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
}

int main(int argc, char **argv) {
    static const uint8_t frame_bytes[A5_2_FRAME_BYTES] = {
        0x78, 0xf1, 0xd4, 0x1a
    };
    static const uint8_t target_ciphertext[32] = {
        0x1c, 0x64, 0x0c, 0x4f, 0x95, 0x12, 0xba, 0x87,
        0x30, 0xa0, 0x27, 0x9d, 0x75, 0x04, 0x67, 0x41,
        0xbe, 0x7c, 0x81, 0x9d, 0xf9, 0x89, 0x3e, 0x12,
        0x15, 0xf9, 0x49, 0x46, 0x76, 0xaa, 0xd7, 0x9c
    };

    uint8_t key[A5_2_KEY_BYTES];
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
    a5_2_crypt(key, load_be32(frame_bytes), plaintext, ciphertext, sizeof(ciphertext));

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
