/* key_mode=weak_prng_seeded variant=randomized challenge=RC5-CBC */
/* canonical_flag=26125bdc1697b80cc6b9e67afa291faef05f797aca35e3587cb36a1a13aa28ad */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/rc5.h"

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
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <64-hex-chars>\n", argv[0]);
        return 1;
    }

    uint8_t key[16];
    insecure_key_generate(key, sizeof(key));

    const uint8_t iv[RC5_BLOCK_SIZE] = {
        0x5c, 0xe1, 0xc3, 0xb0, 0x34, 0xd3, 0x21, 0x91
    };

    const uint8_t target_ciphertext[32] = {
        0xd4, 0x5f, 0xc2, 0x39, 0xd3, 0x99, 0x71, 0xf1,
        0x6f, 0x5a, 0x03, 0x7a, 0xe7, 0xcf, 0x92, 0x7d,
        0x5d, 0xc0, 0xf1, 0xbb, 0x49, 0x8b, 0xd7, 0x8d,
        0xc8, 0x7f, 0xbf, 0xe2, 0x69, 0x49, 0x43, 0x27
    };

    uint8_t plaintext[32];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    rc5_ctx ctx;
    if (rc5_set_key(&ctx, key, sizeof(key), RC5_DEFAULT_ROUNDS) != 0) {
        fprintf(stderr, "Key setup failed.\n");
        return 1;
    }

    uint8_t ciphertext[32];
    rc5_cbc_encrypt(&ctx, iv, plaintext, ciphertext, sizeof(ciphertext));

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 1;
}
