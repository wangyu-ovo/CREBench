/* key_mode=weak_prng_seeded variant=randomized challenge=SHACAL-2 */
/* canonical_flag=cb05bbf9bb43157d1446cd259c5ee25bcd04ef3c107afac7864184a7c2b3786c */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/shacal2.h"

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

    unsigned char key[32];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    const unsigned char iv[SHACAL2_BLOCK_SIZE] = {
        0xdb, 0xeb, 0x53, 0x1f, 0x4b, 0xa1, 0x19, 0xef,
        0x36, 0x84, 0x8e, 0x74, 0x28, 0x9a, 0x45, 0xb7,
        0xfa, 0xf7, 0xaf, 0x05, 0x40, 0x2c, 0xab, 0xf7,
        0x79, 0x36, 0x8f, 0x1d, 0x16, 0x40, 0x96, 0x8c
    };

    const unsigned char target_ciphertext[SHACAL2_BLOCK_SIZE] = {
        0xfc, 0xc6, 0x9f, 0x90, 0x81, 0x7c, 0xad, 0xa3,
        0x89, 0xca, 0xbb, 0x40, 0x42, 0x88, 0xa2, 0x72,
        0x24, 0xf2, 0xc3, 0xfe, 0x7b, 0x54, 0xf2, 0xc8,
        0x55, 0xee, 0xb1, 0x51, 0x7f, 0x75, 0x57, 0x77
    };

    unsigned char plaintext[SHACAL2_BLOCK_SIZE];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    shacal2_ctx ctx;
    if (shacal2_set_key(&ctx, key, sizeof(key)) != 0) {
        fprintf(stderr, "Key setup failed.\n");
        return 1;
    }

    unsigned char ciphertext[SHACAL2_BLOCK_SIZE];
    shacal2_cbc_encrypt(&ctx, iv, plaintext, ciphertext, sizeof(ciphertext));

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 1;
}
