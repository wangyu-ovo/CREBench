/* key_mode=fragmented_build variant=randomized challenge=TEA */
/* canonical_flag=63c0455a63f60727 */
#include "../src/tea.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
        fprintf(stderr, "Usage: %s <16-hex-chars>\n", argv[0]);
        return 1;
    }

    /* Template step 1: key material always comes from key_source.c. */
    uint8_t key[TEA_KEY_BYTES];
    insecure_key_generate(key, sizeof(key));

    /* Template step 3: keep the target buffer local to the wrapper. */
    const uint8_t target_ciphertext[TEA_BLOCK_BYTES] = {
        0xba, 0x58, 0x77, 0x86, 0x13, 0x1c, 0xa2, 0x67
    };

    uint8_t plaintext[TEA_BLOCK_BYTES];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 16 hex chars (8 bytes).\n");
        return 1;
    }

    /* Template step 4: algorithm-specific context + encrypt call stay unchanged. */
    uint8_t ciphertext[TEA_BLOCK_BYTES];
    tea_enc(plaintext, ciphertext, key);

    /* Template step 5: compare against the embedded target. */
    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 1;
}
