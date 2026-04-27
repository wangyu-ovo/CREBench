/* key_mode=fragmented_build variant=randomized challenge=Lucifer-128-ECB */
/* canonical_flag=4cde8c3e531d8400971b8e064f31e7c627fb6bd1ece498fb510b10fb2756fb21 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/lucifer.h"

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

    uint8_t key[LUCIFER_KEY_SIZE];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    const uint8_t target_ciphertext[32] = {
        0x16, 0xda, 0xa6, 0xec, 0xe6, 0x55, 0xc8, 0x97,
        0xbb, 0x3e, 0x93, 0x92, 0x28, 0xf2, 0x7a, 0x98,
        0x78, 0xd0, 0x9d, 0xf2, 0x29, 0x3e, 0xe4, 0xf3,
        0xcf, 0x9e, 0x27, 0x12, 0xb0, 0x92, 0x43, 0xd5
    };

    uint8_t plaintext[32];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    lucifer_ctx ctx;
    lucifer_set_encrypt_key(&ctx, key);

    uint8_t ciphertext[32];
    lucifer_ecb_encrypt(&ctx, plaintext, ciphertext, sizeof(ciphertext));

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 1;
}
