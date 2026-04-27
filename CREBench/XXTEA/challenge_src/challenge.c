#include "../src/xxtea.h"
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
        fprintf(stderr, "Usage: %s <32-hex-chars>\n", argv[0]);
        return 1;
    }

    uint8_t key[XXTEA_KEY_BYTES];
    insecure_key_generate(key, sizeof(key));

    const uint8_t target_ciphertext[XXTEA_BLOCK_BYTES] = {
        0x9a, 0xa0, 0xb6, 0x46, 0x93, 0xda, 0x52, 0x9d,
        0x3d, 0x6c, 0xb7, 0x70, 0x60, 0x68, 0x3f, 0x3e
    };

    uint8_t plaintext[XXTEA_BLOCK_BYTES];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 32 hex chars (16 bytes).\n");
        return 1;
    }

    uint8_t ciphertext[XXTEA_BLOCK_BYTES];
    xxtea_enc(plaintext, ciphertext, key);

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 2;
}
