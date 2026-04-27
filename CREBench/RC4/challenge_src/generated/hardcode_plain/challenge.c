/* key_mode=hardcode_plain variant=randomized challenge=RC4 */
/* canonical_flag=d69813ad06d6a43efc47f52675e08cec6bd01431983530463afa2758da7472eb */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/rc4.h"

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

    uint8_t key[RC4_KEY_BYTES];
    uint8_t plaintext[32];
    uint8_t ciphertext[32];
    rc4_ctx ctx;

    static const uint8_t target_ciphertext[32] = {
        0x91, 0x5c, 0x10, 0xbc, 0x8b, 0x9a, 0x54, 0xd2,
        0x12, 0x5b, 0x79, 0xdb, 0x66, 0xf6, 0x20, 0xdc,
        0x00, 0x1c, 0x00, 0xcd, 0xee, 0x47, 0x59, 0x25,
        0xb8, 0xfb, 0x44, 0x82, 0x40, 0x5e, 0xe9, 0x8e
    };

    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    insecure_key_generate(key, sizeof(key));
    rc4_init(&ctx, key, sizeof(key));
    rc4_crypt(&ctx, plaintext, ciphertext, sizeof(ciphertext));

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    if (memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0) {
        puts("Match: True");
        return 0;
    }

    puts("Match: False");
    return 2;
}
