/* key_mode=weak_prng_seeded variant=randomized challenge=SKIPJACK */
/* canonical_flag=37ee4a6094b551403bea3084f57cda817566da9d3af666ade43466c6bac30b7a */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/skipjack.h"

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

    uint8_t key[SKIPJACK_KEY_SIZE];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    const uint8_t iv[SKIPJACK_BLOCK_SIZE] = {
        0x82, 0x27, 0xb5, 0xd6, 0x20, 0xc1, 0x8a, 0x34
    };

    const uint8_t target_ciphertext[32] = {
        0x4f, 0x27, 0xf7, 0x39, 0xe2, 0x0a, 0x5e, 0xea,
        0x67, 0x69, 0x60, 0x42, 0xee, 0x33, 0x88, 0x4c,
        0x16, 0x85, 0xc0, 0x7c, 0x2b, 0x00, 0xfb, 0xb4,
        0xf6, 0x45, 0x33, 0x95, 0x03, 0x28, 0x0d, 0x1a
    };

    uint8_t plaintext[32];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    skipjack_ctx ctx;
    if (skipjack_set_key(&ctx, key, sizeof(key)) != 0) {
        fprintf(stderr, "Key setup failed.\n");
        return 1;
    }

    uint8_t ciphertext[32];
    skipjack_cbc_encrypt(&ctx, iv, plaintext, ciphertext, sizeof(ciphertext));

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 1;
}
