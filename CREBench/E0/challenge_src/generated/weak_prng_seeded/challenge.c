/* key_mode=weak_prng_seeded variant=randomized challenge=E0 */
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
        0x06, 0x5f, 0xf2, 0x22, 0x68, 0x79, 0x42, 0x9e,
        0xe9, 0xb8, 0xd3, 0x00, 0xbd, 0x61, 0x49, 0x7c,
        0x34, 0xd2, 0x12, 0xd7, 0xb9, 0xc3, 0x9f, 0x9c,
        0xa4, 0x4a, 0xf5, 0xeb, 0xaa, 0x17, 0x18, 0x8d
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
