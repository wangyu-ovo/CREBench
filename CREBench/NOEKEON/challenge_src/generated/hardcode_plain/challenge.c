/* key_mode=hardcode_plain variant=randomized challenge=NOEKEON */
/* canonical_flag=b62e1a00b71ebe967e2e15bdf3a5e5dae3d3311e3e6a4aa60229ec3a34f99b5b */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/noekeon.h"

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

    unsigned char key[NOEKEON_KEY_SIZE];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    const unsigned char iv[NOEKEON_BLOCK_SIZE] = {
        0xf1, 0xf5, 0x79, 0x64, 0x9e, 0x51, 0x6e, 0xea,
        0xca, 0x29, 0x88, 0xe3, 0x6a, 0xac, 0xf0, 0x2f
    };

    const unsigned char target_ciphertext[32] = {
        0x95, 0xfb, 0xae, 0xce, 0x54, 0x7b, 0x9b, 0x16,
        0x03, 0xd5, 0xe4, 0x81, 0x64, 0x33, 0xb1, 0xf8,
        0x45, 0x46, 0xd1, 0xda, 0xb6, 0xb2, 0x03, 0x54,
        0x49, 0xb9, 0x75, 0x4c, 0xa9, 0x1b, 0x04, 0x37
    };

    unsigned char plaintext[32];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    noekeon_ctx ctx;
    if (noekeon_set_key(&ctx, key, sizeof(key)) != 0) {
        fprintf(stderr, "Key setup failed.\n");
        return 1;
    }

    unsigned char ciphertext[32];
    noekeon_cbc_encrypt(&ctx, iv, plaintext, ciphertext, sizeof(ciphertext));

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 1;
}
