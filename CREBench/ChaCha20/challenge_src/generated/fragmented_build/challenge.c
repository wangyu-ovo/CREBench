/* key_mode=fragmented_build variant=randomized challenge=ChaCha20 */
/* canonical_flag=53535a92ee92e3aaef03b97d86baa8637fe13109944b9cd1978e064e3242926b */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/chacha20.h"

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
    static const uint8_t nonce[CHACHA20_NONCE_BYTES] = {
        0xb3, 0x1f, 0x2a, 0x2e, 0x56, 0x81, 0x54, 0xe3,
        0xc8, 0x66, 0xb8, 0x50
    };
    static const uint8_t target_ciphertext[32] = {
        0x4d, 0xc2, 0x6e, 0x8a, 0x1b, 0x22, 0xaa, 0xce,
        0xca, 0x10, 0xcb, 0x4f, 0x18, 0x6a, 0x52, 0x36,
        0x38, 0x38, 0x24, 0x5c, 0x18, 0x7d, 0x84, 0x7b,
        0x5c, 0x10, 0xe2, 0xb5, 0xb9, 0x6f, 0x39, 0x3d
    };

    uint8_t key[CHACHA20_KEY_BYTES];
    uint8_t plaintext[32];
    uint8_t ciphertext[32];

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <64-hex-chars>\n", argv[0]);
        return 1;
    }

    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    insecure_key_generate(key, sizeof(key));
    chacha20_crypt(key, nonce, 1U, plaintext, ciphertext, sizeof(ciphertext));

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
