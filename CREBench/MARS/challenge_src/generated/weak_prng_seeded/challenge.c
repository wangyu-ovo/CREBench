/* key_mode=weak_prng_seeded variant=randomized challenge=MARS */
/* canonical_flag=ad98c7a9df4da30fbb008c402795347a233834a81f33fbb0dce7240acb860edf */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/mars.h"

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

    const unsigned char iv[MARS_BLOCK_SIZE] = {
        0x1a, 0x09, 0xca, 0x18, 0x28, 0xa4, 0xb8, 0x28,
        0x8e, 0x7f, 0xe7, 0xf0, 0xa0, 0xfd, 0xc2, 0x52
    };

    const unsigned char target_ciphertext[32] = {
        0x6d, 0xb5, 0x69, 0x3f, 0x3e, 0x47, 0x2c, 0x7e,
        0xb1, 0x9b, 0x19, 0xd6, 0x32, 0x49, 0xd6, 0x23,
        0xba, 0xe4, 0xdc, 0xfd, 0x51, 0xd1, 0x3a, 0xc6,
        0x15, 0x84, 0xf6, 0x4f, 0x64, 0x9a, 0x80, 0xfb
    };

    unsigned char plaintext[32];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    mars_ctx ctx;
    if (mars_set_key(&ctx, key, sizeof(key)) != 0) {
        fprintf(stderr, "Key setup failed.\n");
        return 1;
    }

    unsigned char ciphertext[32];
    mars_cbc_encrypt(&ctx, iv, plaintext, ciphertext, sizeof(ciphertext));

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 1;
}
