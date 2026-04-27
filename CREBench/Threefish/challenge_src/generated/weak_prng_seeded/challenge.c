/* key_mode=weak_prng_seeded variant=randomized challenge=Threefish */
/* canonical_flag=995dd9c9d8f658022ade336e8bead5a37bc8c1e5b6c12bdb9d797a3f6b4cc39838ae128e992eee80cb12971cb44898e1efa7a8b04fd8dcc99f1dbdc7b7d35e2d */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/threefish.h"

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
        fprintf(stderr, "Usage: %s <128-hex-chars>\n", argv[0]);
        return 1;
    }

    unsigned char key[THREEFISH_512_KEY_SIZE];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    const unsigned char iv[THREEFISH_512_BLOCK_SIZE] = {
        0x46, 0x0a, 0x62, 0x54, 0x78, 0xb9, 0x9b, 0x3c,
        0x92, 0x55, 0xb9, 0x98, 0x41, 0xf2, 0xe2, 0x9d,
        0x16, 0x1f, 0x1f, 0xad, 0x21, 0xba, 0x64, 0x7a,
        0x91, 0x65, 0x13, 0x9d, 0x83, 0xd5, 0x6c, 0x64,
        0x60, 0xfb, 0x0a, 0x5b, 0xcb, 0x49, 0x61, 0x2b,
        0x5b, 0x73, 0x2a, 0x0c, 0x0b, 0xf7, 0xe5, 0x5a,
        0x80, 0x0d, 0xce, 0x6e, 0x70, 0xf2, 0x7d, 0xe0,
        0xb7, 0xa5, 0x72, 0x4b, 0x1d, 0x0e, 0xd6, 0x8f
    };

    const unsigned char target_ciphertext[THREEFISH_512_BLOCK_SIZE] = {
        0x23, 0xbb, 0x6d, 0xd5, 0x8b, 0xa3, 0xf6, 0xa7,
        0x54, 0xaa, 0x13, 0x1c, 0xc7, 0x22, 0xfd, 0x1e,
        0xad, 0xa0, 0x7c, 0x48, 0xfc, 0x20, 0x64, 0xbb,
        0xc6, 0xd8, 0x70, 0x2e, 0xef, 0x12, 0xd6, 0x8a,
        0xab, 0x00, 0x10, 0x9b, 0x0d, 0x8e, 0xe1, 0x58,
        0x52, 0x1b, 0x7a, 0x30, 0xce, 0x66, 0xbb, 0xc4,
        0x9d, 0x9e, 0x4e, 0x32, 0xa9, 0x0c, 0x6a, 0xd2,
        0x06, 0xeb, 0xf3, 0xe8, 0x77, 0xd3, 0x70, 0x47
    };

    unsigned char plaintext[THREEFISH_512_BLOCK_SIZE];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 128 hex chars (64 bytes).\n");
        return 1;
    }

    threefish512_ctx ctx;
    if (threefish512_set_key(&ctx, key, sizeof(key)) != 0) {
        fprintf(stderr, "Key setup failed.\n");
        return 1;
    }

    unsigned char ciphertext[THREEFISH_512_BLOCK_SIZE];
    threefish512_cbc_encrypt(&ctx, iv, plaintext, ciphertext, sizeof(ciphertext));

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 1;
}
