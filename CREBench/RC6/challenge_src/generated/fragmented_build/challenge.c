/* key_mode=fragmented_build variant=randomized challenge=RC6 */
/* canonical_flag=7f99111f347562684e18a37dca254ba9b71307456f6523a398fb063acea71afe */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/rc6.h"

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

    uint8_t key[16];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    const uint8_t iv[RC6_BLOCK_SIZE] = {
        0x87, 0xb6, 0x3e, 0x9c, 0x8d, 0x70, 0x49, 0x89,
        0xe5, 0xbd, 0xd1, 0xdd, 0x0c, 0x01, 0x72, 0x55
    };

    const uint8_t target_ciphertext[32] = {
        0x64, 0xdd, 0x14, 0xcb, 0xec, 0xe5, 0x0a, 0xc2,
        0x86, 0x37, 0x83, 0x5e, 0xff, 0x01, 0x12, 0x41,
        0x66, 0x4d, 0x99, 0xb7, 0x9a, 0x16, 0xa6, 0x8e,
        0x74, 0x3c, 0x26, 0x6c, 0xc9, 0xab, 0xb1, 0xcd
    };

    uint8_t plaintext[32];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    rc6_ctx ctx;
    if (rc6_set_key(&ctx, key, sizeof(key)) != 0) {
        fprintf(stderr, "Key setup failed.\n");
        return 1;
    }

    uint8_t ciphertext[32];
    rc6_cbc_encrypt(&ctx, iv, plaintext, ciphertext, sizeof(ciphertext));

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 1;
}
