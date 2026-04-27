/* key_mode=fragmented_build variant=randomized challenge=Crypto-1 */
/* canonical_flag=ea7fa6d2995a6d44f2e27c41a819417a0dc897d206cc45da040603c99135c2a9 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../src/crypto1_stream.h"

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
    static const uint8_t iv[CRYPTO1_IV_BYTES] = {
        0x85, 0xfa, 0xa3, 0xc9, 0x9c, 0x17, 0xc7, 0x7d
    };
    static const uint8_t target_ciphertext[32] = {
        0x01, 0x1d, 0xbb, 0x2f, 0x50, 0xd0, 0xad, 0x01,
        0xf6, 0xaf, 0x12, 0x3d, 0x24, 0x18, 0x8d, 0x11,
        0xc8, 0x34, 0x58, 0xfe, 0x6d, 0x61, 0x61, 0xd3,
        0x75, 0x2b, 0x19, 0x0e, 0x42, 0x5e, 0xaf, 0x00
    };

    uint8_t key[CRYPTO1_KEY_BYTES];
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
    crypto1_crypt(key, iv, plaintext, ciphertext, sizeof(ciphertext));

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
