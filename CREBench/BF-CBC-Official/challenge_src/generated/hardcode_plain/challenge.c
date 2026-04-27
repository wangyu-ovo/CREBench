/* key_mode=hardcode_plain variant=randomized challenge=BF-CBC-Official */
/* canonical_flag=e5f849d32149fac307c739c3684de2d6 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/blowfish.h"

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
        fprintf(stderr, "Usage: %s <32-hex-chars>\n", argv[0]);
        return 1;
    }

    /* Template step 1: key material always comes from key_source.c. */
    unsigned char key[16];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    /* Template step 2: keep IV handling local to the wrapper. */
    const unsigned char iv_init[8] = {
        0x9d, 0x6e, 0x99, 0xef, 0x34, 0x22, 0xd9, 0xb4
    };

    /* Template step 3: keep the target buffer local to the wrapper. */
    const unsigned char target_ciphertext[16] = {
        0x27, 0x63, 0x07, 0x7a, 0xdf, 0xa0, 0x31, 0xbb,
        0x87, 0x37, 0x2c, 0xad, 0xf3, 0xfd, 0x2b, 0xfa
    };

    unsigned char plaintext[16];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 32 hex chars (16 bytes).\n");
        return 1;
    }

    /* Template step 4: algorithm-specific context + encrypt call stay unchanged. */
    bf_key ctx;
    bf_set_key(&ctx, sizeof(key), key);
    unsigned char ciphertext[16];
    bf_cbc_encrypt(&ctx, iv_init, plaintext, ciphertext, sizeof(ciphertext));

    /* Template step 5: compare against the embedded target. */
    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");

    return same ? 0 : 1;
}
