/* key_mode=hardcode_plain variant=randomized challenge=CAST5 */
/* canonical_flag=37a740c0ea9b7629d52b3a3987675fe6bf4a239e7e848a3fb2b8008b5055ca2e */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/cast5.h"

extern void insecure_key_generate(uint8_t *key, size_t key_len);

static int hex_char_to_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex(const char *hex, unsigned char *out, size_t out_len)
{
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

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <64-hex-chars>\n", argv[0]);
        return 1;
    }

    /* Template step 1: key material always comes from key_source.c. */
    unsigned char key[16];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    /* Template step 2: keep IV handling local to the wrapper. */
    const unsigned char iv_init[CAST5_BLOCK_SIZE] = {
        0xed, 0xdc, 0xfb, 0xfd, 0x69, 0x68, 0x3b, 0x94
    };

    /* Template step 3: keep the target buffer local to the wrapper. */
    const unsigned char target_ciphertext[32] = {
        0xe5, 0x1a, 0x70, 0x83, 0xb1, 0xd5, 0xfc, 0xb6,
        0xe2, 0x64, 0x1f, 0xb7, 0xd1, 0x69, 0x82, 0x2b,
        0x35, 0xf5, 0xf5, 0x1a, 0xf2, 0x1c, 0x96, 0x75,
        0x0a, 0x5c, 0xcd, 0x6c, 0x5b, 0xcd, 0xcd, 0x9a
    };

    unsigned char plaintext[32];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    /* Template step 4: algorithm-specific context + encrypt call stay unchanged. */
    cast5_ctx ctx;
    if (cast5_set_key(&ctx, key, sizeof(key)) != 0) {
        return 1;
    }

    unsigned char ciphertext[32];
    cast5_cbc_encrypt(&ctx, iv_init, plaintext, ciphertext, sizeof(ciphertext));

    /* Template step 5: compare against the embedded target. */
    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 1;
}
