/* key_mode=weak_prng_seeded variant=randomized challenge=MISTY1-64 */
/* canonical_flag=c9dcc5f2845b8aa3c9289cbb781fa729992d703dc01d91d2e58a5d20f45402363b95618b7be29c6ca6f68a7704ab00826eb5e65d2854a6e78ad3150fcfcbc630 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/misty1.h"

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
        fprintf(stderr, "Usage: %s <128-hex-chars>\n", argv[0]);
        return 1;
    }

    uint8_t key[MISTY1_KEY_SIZE];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    const uint8_t target_ciphertext[64] = {
        0xac, 0x82, 0xf2, 0xa3, 0xb0, 0x7d, 0xd2, 0x8b,
        0x2a, 0x8a, 0xb4, 0x12, 0xd5, 0x7b, 0xd5, 0xd8,
        0xb5, 0xd8, 0xc9, 0x35, 0x1a, 0xbe, 0x8a, 0xc0,
        0x47, 0xb5, 0x86, 0xf6, 0xb1, 0xee, 0x65, 0x9f,
        0x79, 0xbd, 0x64, 0xac, 0x81, 0xbf, 0xa8, 0xbd,
        0xec, 0x59, 0x0c, 0xc6, 0x56, 0x60, 0x67, 0x4b,
        0x29, 0xd9, 0x8e, 0xb9, 0xb2, 0x94, 0xac, 0xd8,
        0xed, 0xb4, 0xe3, 0x02, 0xc9, 0xdd, 0xf4, 0x85
    };

    uint8_t plaintext[64];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 128 hex chars (64 bytes).\n");
        return 1;
    }

    misty1_ctx ctx;
    if (misty1_set_key(&ctx, key) != 0) {
        fprintf(stderr, "Key setup failed.\n");
        return 1;
    }

    uint8_t ciphertext[64];
    misty1_ecb_encrypt(&ctx, plaintext, ciphertext, sizeof(ciphertext));

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 1;
}
