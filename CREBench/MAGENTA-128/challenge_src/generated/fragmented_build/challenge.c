/* key_mode=fragmented_build variant=randomized challenge=MAGENTA-128 */
/* canonical_flag=6ac6661437a3ebc1c3f909ec51fc684d8bd56cb48ed2b289b20b6d41ebba6ba4 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/magenta.h"

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

    uint8_t key[MAGENTA_KEY_SIZE];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    const uint8_t iv[MAGENTA_BLOCK_SIZE] = {
        0x2a, 0x6f, 0x00, 0x95, 0xac, 0x25, 0xa7, 0xe0,
        0x88, 0x29, 0x50, 0xcf, 0xc2, 0x06, 0xe8, 0x06
    };

    const uint8_t target_ciphertext[32] = {
        0x42, 0x78, 0x47, 0x78, 0xbf, 0x80, 0xf1, 0xb9,
        0xf0, 0x77, 0x2c, 0x97, 0xa4, 0xe5, 0x6c, 0x5c,
        0xfc, 0x42, 0x5c, 0xe4, 0xca, 0xfe, 0xe7, 0xc9,
        0xac, 0x3b, 0xb3, 0x54, 0xb4, 0x42, 0x2a, 0xe7
    };

    uint8_t plaintext[32];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    magenta_ctx ctx;
    if (magenta_set_key(&ctx, key, sizeof(key)) != 0) {
        fprintf(stderr, "Key setup failed.\n");
        return 1;
    }

    uint8_t ciphertext[32];
    magenta_cbc_encrypt(&ctx, iv, plaintext, ciphertext, sizeof(ciphertext));

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 1;
}
