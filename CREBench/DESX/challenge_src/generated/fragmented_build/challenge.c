/* key_mode=fragmented_build variant=randomized challenge=DESX */
/* canonical_flag=6f381a6bd9f1be2f53893ea8f85083703562bd47cea9fa458abd4028276179a9 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/desx.h"

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
    uint8_t key[DESX_KEY_SIZE];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    /* Template step 2: keep IV handling local to the wrapper. */
    const uint8_t iv_init[DESX_BLOCK_SIZE] = {
        0x3e, 0xbe, 0xc1, 0xc2, 0x1e, 0x3f, 0x16, 0x92
    };

    /* Template step 3: keep the target buffer local to the wrapper. */
    const uint8_t target_ciphertext[32] = {
        0x6e, 0x8d, 0x9a, 0xa5, 0x2f, 0xf0, 0x1d, 0xf2,
        0xf0, 0x15, 0x8a, 0x9e, 0xcc, 0x27, 0x7b, 0xff,
        0x8c, 0xdc, 0x88, 0x3a, 0xe9, 0x43, 0x30, 0xf8,
        0xbd, 0xde, 0xa5, 0x91, 0x8b, 0x8e, 0xba, 0x31
    };

    uint8_t plaintext[32];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    /* Template step 4: algorithm-specific context + encrypt call stay unchanged. */
    desx_ctx ctx;
    if (desx_set_key(&ctx, key, sizeof(key)) != 0) {
        fprintf(stderr, "Key setup failed.\n");
        return 1;
    }

    uint8_t ciphertext[32];
    desx_cbc_encrypt(&ctx, iv_init, plaintext, ciphertext, sizeof(ciphertext));

    /* Template step 5: compare against the embedded target. */
    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 1;
}
