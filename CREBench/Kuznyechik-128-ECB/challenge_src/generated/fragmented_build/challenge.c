/* key_mode=fragmented_build variant=randomized challenge=Kuznyechik-128-ECB */
/* canonical_flag=f2e55e6ecdc7adf46adafac99b08662ee4234749f7d973fab460cee2cc97984e */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/kuznyechik.h"

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
        fprintf(stderr, "Usage: %s <64-hex-chars>\n", argv[0]);
        return 1;
    }

    unsigned char key[KUZNYECHIK_KEY_SIZE];
    insecure_key_generate((uint8_t *)key, sizeof(key));

    const unsigned char target_ciphertext[32] = {
        0x08, 0xae, 0x1e, 0x67, 0x4a, 0x8b, 0xf8, 0xf1,
        0x96, 0xdc, 0xca, 0xa9, 0xfa, 0x5c, 0x60, 0x59,
        0x4e, 0x79, 0x00, 0xfc, 0xe3, 0x79, 0xff, 0x85,
        0xda, 0xe6, 0xef, 0x9d, 0xfa, 0x9a, 0x3d, 0x3e
    };

    unsigned char plaintext[32];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    struct kuznyechik_subkeys subkeys;
    kuznyechik_set_key(&subkeys, key);

    unsigned char ciphertext[32];
    kuznyechik_ecb_encrypt(&subkeys, plaintext, ciphertext, sizeof(ciphertext));

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 1;
}
