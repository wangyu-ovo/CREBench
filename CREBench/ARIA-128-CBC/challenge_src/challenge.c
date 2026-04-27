#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/aria.h"

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

    const unsigned char ctx_target[32] = {
        0xd9, 0xac, 0x67, 0x66, 0x5f, 0x8d, 0x23, 0x1e,
        0x7b, 0xa2, 0x90, 0xb9, 0xd4, 0x2d, 0x7a, 0x65,
        0xa5, 0x44, 0x8a, 0x32, 0x11, 0xe6, 0x75, 0xe2,
        0x47, 0xa8, 0x7a, 0x0c, 0xb2, 0xf4, 0xb4, 0x89
    };

    unsigned char key[16];
    insecure_key_generate((uint8_t *)key, sizeof(key));
    const unsigned char iv_init[16] = {
        0x45, 0x18, 0xee, 0xb5, 0x48, 0x48, 0x2e, 0x6c,
        0x02, 0xce, 0x25, 0xb6, 0xa1, 0x3f, 0xae, 0x94
    };

    unsigned char plaintext[32]; /* 2 blocks */
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    /* Our ARIA-CBC */
    ARIA_KEY aria_key;
    if (aria_set_encrypt_key(key, 128, &aria_key) != 0) {
        // fprintf(stderr, "Failed to set ARIA key\n");
        return 1;
    }
    unsigned char ct_mine[32];
    aria_cbc_encrypt(&aria_key, iv_init, plaintext, ct_mine, sizeof(ct_mine));

    printf("Ciphertext(hex): ");
    print_hex(ct_mine, sizeof(ct_mine));
    printf("\n");

    int same = memcmp(ct_mine, ctx_target, sizeof(ct_mine)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 2;
}
