/* key_mode=weak_prng_seeded variant=randomized challenge=LOKI97 */
/* canonical_flag=b71bd2fa62e987bd5ed5e227ffe7d8d992fca702ac1e627e1352745e1bfb857d */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/loki97.h"

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

    uint8_t key[32];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    const uint8_t iv[LOKI97_BLOCK_SIZE] = {
        0x9a, 0xec, 0x79, 0xc7, 0xd8, 0x34, 0xe4, 0xaa,
        0x33, 0x1c, 0x4b, 0x6a, 0x1b, 0x80, 0x39, 0xcf
    };

    const uint8_t target_ciphertext[32] = {
        0xf1, 0xcf, 0x0f, 0x53, 0x45, 0x31, 0x09, 0x00,
        0xce, 0x4a, 0x43, 0xf6, 0x8d, 0xca, 0xeb, 0x5b,
        0xd5, 0x02, 0xcf, 0x0e, 0xd0, 0x08, 0x52, 0x08,
        0x6b, 0x88, 0xb8, 0xfa, 0x12, 0x54, 0x61, 0x20
    };

    uint8_t plaintext[32];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    loki97_ctx ctx;
    if (loki97_set_key(&ctx, key, sizeof(key)) != 0) {
        fprintf(stderr, "Key setup failed.\n");
        return 1;
    }

    uint8_t ciphertext[32];
    loki97_cbc_encrypt(&ctx, iv, plaintext, ciphertext, sizeof(ciphertext));

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 1;
}
