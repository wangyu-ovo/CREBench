/* key_mode=weak_prng_seeded variant=randomized challenge=DES */
/* canonical_flag=52b992307d0819318c416b0110e525a91921d3164d1db17c6d405434a5bdcade */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/des.h"

extern void insecure_key_generate(uint8_t *key, size_t key_len);

static int hex_char_to_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex(const char *hex, uint8_t *out, size_t out_len)
{
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

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <64-hex-chars>\n", argv[0]);
        return 1;
    }

    /* Template step 1: key material always comes from key_source.c. */
    uint8_t key[DES_KEY_SIZE];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    /* Template step 2: keep IV handling local to the wrapper. */
    const uint8_t iv_init[DES_BLOCK_SIZE] = {
        0x05, 0x40, 0xdd, 0x27, 0x23, 0x29, 0x08, 0x02
    };

    /* Template step 3: keep the target buffer local to the wrapper. */
    const uint8_t target_ciphertext[32] = {
        0x15, 0x02, 0x8d, 0x0d, 0x2a, 0xf9, 0x20, 0x66,
        0x90, 0xaf, 0x96, 0xb7, 0xfe, 0x7d, 0x4f, 0xac,
        0x27, 0xf8, 0xab, 0xb4, 0x01, 0xdf, 0x1d, 0x07,
        0xed, 0x9e, 0x85, 0xc7, 0x67, 0x39, 0x88, 0x3b
    };

    uint8_t plaintext[32];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    /* Template step 4: algorithm-specific context + encrypt call stay unchanged. */
    des_ctx ctx;
    if (des_set_key(&ctx, key) != 0) {
        fprintf(stderr, "Key setup failed.\n");
        return 1;
    }

    uint8_t ciphertext[32];
    des_cbc_encrypt(&ctx, iv_init, plaintext, ciphertext, sizeof(ciphertext));

    /* Template step 5: compare against the embedded target. */
    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 1;
}
