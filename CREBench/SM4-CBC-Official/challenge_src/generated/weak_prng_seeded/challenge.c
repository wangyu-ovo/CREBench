/* key_mode=weak_prng_seeded variant=randomized challenge=SM4-CBC-Official */
/* canonical_flag=a454eec650748622d2421da0c4441e4778a3ecbc0c68451e115f4521b533f478 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/sm4.h"

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

    unsigned char key[SM4_KEY_BYTES];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    const unsigned char iv[SM4_BLOCK_BYTES] = {
        0x62, 0x03, 0x73, 0x1c, 0xd2, 0x22, 0x0b, 0x37,
        0xe7, 0xe2, 0xea, 0x9f, 0x12, 0xd6, 0x39, 0xdc
    };

    const unsigned char target_ciphertext[32] = {
        0x4c, 0x5c, 0xc8, 0xdd, 0x6f, 0x56, 0x02, 0x52,
        0x1d, 0x36, 0xbc, 0x0e, 0xec, 0x98, 0xdf, 0x33,
        0x36, 0xdf, 0x73, 0x3f, 0x19, 0x42, 0x1f, 0x15,
        0x38, 0xe7, 0x31, 0xa5, 0x7f, 0xb7, 0xc5, 0x3c
    };

    unsigned char plaintext[32];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    sm4_ctx ctx;
    sm4_key_expand(&ctx, key);

    unsigned char ciphertext[32];
    sm4_cbc_encrypt(&ctx, iv, plaintext, ciphertext, sizeof(ciphertext));

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 1;
}
