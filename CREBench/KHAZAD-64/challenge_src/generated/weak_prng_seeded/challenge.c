/* key_mode=weak_prng_seeded variant=randomized challenge=KHAZAD-64 */
/* canonical_flag=d1061c0085ab775d169f158c62c2ad5d38a2521552cd0f239896a70deca827f4 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/khazad.h"

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

    uint8_t key[KHAZAD_KEY_SIZE];
    insecure_key_generate(key, sizeof(key));

    const uint8_t target_ciphertext[32] = {
        0x98, 0x6b, 0xc0, 0x39, 0x93, 0xe7, 0x18, 0x56,
        0xd8, 0x2c, 0x20, 0x2b, 0xa2, 0x3b, 0x91, 0x0f,
        0x55, 0xec, 0x2d, 0xbc, 0x02, 0xf2, 0xee, 0x8c,
        0xab, 0x18, 0x5e, 0x5b, 0x42, 0xd8, 0xc2, 0x40
    };

    uint8_t plaintext[32];
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 64 hex chars (32 bytes).\n");
        return 1;
    }

    our_khazad_ctx ctx;
    if (our_khazad_set_key(&ctx, key) != 0) {
        fprintf(stderr, "Key setup failed.\n");
        return 1;
    }

    uint8_t ciphertext[32];
    our_khazad_ecb_encrypt(&ctx, plaintext, ciphertext, sizeof(ciphertext));

    printf("Ciphertext(hex): ");
    print_hex(ciphertext, sizeof(ciphertext));
    printf("\n");

    int same = memcmp(ciphertext, target_ciphertext, sizeof(ciphertext)) == 0;
    printf("Match: %s\n", same ? "True" : "False");
    return same ? 0 : 1;
}
