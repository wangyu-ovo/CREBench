/* key_mode=weak_prng_seeded variant=randomized challenge=AES-128-CBC */
/* canonical_flag=4c715932e60fb56e716a5d9af88f5c5764eaea10fb79399b5dd1b69f960d3253 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/aes.h"

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

    /* Template step 1: key material always comes from key_source.c. */
    unsigned char key[16];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    /* Template step 2: keep IV handling local to the wrapper. */
    const unsigned char iv_init[16] = {
        0xaa, 0x16, 0x73, 0x46, 0x0a, 0x45, 0x95, 0xd9,
        0xec, 0xe4, 0xe8, 0xc3, 0x47, 0x30, 0x78, 0x03
    };

    /* Template step 3: keep the target buffer local to the wrapper. */
    const unsigned char target_ciphertext[32] = {
        0x73, 0xf4, 0xcb, 0x47, 0x19, 0x08, 0xf1, 0x07,
        0x19, 0x77, 0x60, 0x04, 0x98, 0xb7, 0xb5, 0xa2,
        0x7a, 0x97, 0xf3, 0x5f, 0xdb, 0x3e, 0x94, 0xc3,
        0xb6, 0x04, 0xbc, 0x43, 0x24, 0x0d, 0xcd, 0xb0
    };

    unsigned char plaintext[32];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    /* Template step 4: algorithm-specific context + encrypt call stay unchanged. */
    aes128_ctx ctx;
    aes128_key_expand(&ctx, key);
    unsigned char ciphertext[32];
    aes128_cbc_encrypt(&ctx, iv_init, plaintext, ciphertext, sizeof(ciphertext));

    /* Template step 5: compare against the embedded target. */
    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");

    return same ? 0 : 1;
}
