/* key_mode=fragmented_build variant=randomized challenge=E0 */
/* canonical_flag=5d07e9f0b2864a34e95d81269be6737dee209297bec4d63fd6ff04c0faa3b29d */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../src/e0.h"

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

static void print_hex(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
}

int main(int argc, char **argv) {
    static const uint8_t iv[E0_IV_BYTES] = {
        0xbc, 0x97, 0xe8, 0x09, 0x50, 0xeb, 0x87, 0x51,
        0x57, 0x7f
    };
    static const uint8_t target_ciphertext[32] = {
        0xf3, 0xa8, 0xe1, 0xf7, 0x01, 0x27, 0x2e, 0x2d,
        0x81, 0x77, 0xfc, 0x54, 0x5b, 0xb8, 0x47, 0x0e,
        0x9f, 0xc3, 0x06, 0x32, 0x83, 0x33, 0x17, 0xfb,
        0x98, 0x4e, 0x4d, 0x4a, 0xcf, 0xf1, 0x8e, 0x57
    };

    uint8_t key[E0_KEY_BYTES];
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
    e0_crypt(key, iv, plaintext, ciphertext, sizeof(ciphertext));

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
