/* key_mode=weak_prng_seeded variant=randomized challenge=SC2000 */
/* canonical_flag=6b527ad435c5aefbcbfc1f3f9a2b96ed */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/sc2000.h"

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
    unsigned char key[SC2000_KEY_BYTES];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    /* Template step 3: keep the target buffer local to the wrapper. */
    const uint8_t target_ciphertext[SC2000_BLOCK_BYTES] = {
        0x77, 0x6f, 0x9e, 0xa0, 0x3c, 0x2f, 0x5b, 0xa0,
        0x62, 0xa0, 0x29, 0x1a, 0xa4, 0xbb, 0xa9, 0x89
    };

    unsigned char plaintext[SC2000_BLOCK_BYTES];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 32 hex chars (16 bytes).\n");
        return 1;
    }

    /* Template step 4: algorithm-specific context + encrypt call stay unchanged. */
    uint8_t ciphertext[SC2000_BLOCK_BYTES];
    sc2000_enc(plaintext, ciphertext, key);

    /* Template step 5: compare against the embedded target. */
    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 1;
}
