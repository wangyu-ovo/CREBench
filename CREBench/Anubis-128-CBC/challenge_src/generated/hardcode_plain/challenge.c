/* key_mode=hardcode_plain variant=randomized challenge=Anubis-128-CBC */
/* canonical_flag=7cc0cc72b35db4d5ee8e86a0f54cec11ed3c88dc282c2247fafbe94bffc2e493 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/anubis.h"

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

    /* Template step 1: key material always comes from key_source.c. */
    uint8_t key[16];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    /* Template step 2: keep IV handling local to the wrapper. */
    const uint8_t iv[16] = {
        0x4c, 0x73, 0x35, 0x14, 0x1d, 0xc0, 0x0c, 0x0b,
        0x79, 0x7a, 0xcb, 0xe3, 0x4b, 0x76, 0xee, 0xec
    };

    /* Template step 3: keep the target buffer local to the wrapper. */
    const uint8_t target_ciphertext[32] = {
        0xdd, 0x64, 0xb0, 0xf4, 0x3b, 0x7e, 0xa8, 0xe8,
        0x48, 0x26, 0x23, 0x39, 0xcd, 0xbf, 0x14, 0x4c,
        0xcd, 0xae, 0x83, 0xd5, 0x47, 0x71, 0xbf, 0xec,
        0x83, 0x08, 0x01, 0x2d, 0x18, 0xd7, 0x92, 0xaf
    };

    uint8_t plaintext[32];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    /* Template step 4: algorithm-specific context + encrypt call stay unchanged. */
    anubis_ctx ctx;
    if (anubis_set_key(&ctx, key, sizeof(key)) != 0) {
        fprintf(stderr, "Key setup failed.\n");
        return 1;
    }

    uint8_t ciphertext[32];
    anubis_cbc_encrypt(&ctx, iv, plaintext, ciphertext, sizeof(plaintext));

    /* Template step 5: compare against the embedded target. */
    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");

    return same ? 0 : 1;
}
