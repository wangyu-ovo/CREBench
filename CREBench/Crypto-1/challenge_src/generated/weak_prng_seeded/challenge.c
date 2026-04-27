/* key_mode=weak_prng_seeded variant=randomized challenge=Crypto-1 */
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
        0xda, 0x73, 0x6a, 0xdd, 0xe7, 0xd0, 0x63, 0x6d,
        0xbb, 0x63, 0xcd, 0x8b, 0x05, 0x72, 0xdd, 0x03,
        0x50, 0xbc, 0xdf, 0x3f, 0xfc, 0x0c, 0x09, 0xa1,
        0xb3, 0x32, 0xfb, 0x6a, 0x3c, 0x9e, 0x63, 0xc0
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
