#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/sc2000.h"

extern void insecure_key_generate(uint8_t *key, size_t key_len);

static int write_vectors(FILE *out) {
    static const uint8_t plaintexts[5][SC2000_BLOCK_BYTES] = {
        {
            0x6b, 0x52, 0x7a, 0xd4, 0x35, 0xc5, 0xae, 0xfb,
            0xcb, 0xfc, 0x1f, 0x3f, 0x9a, 0x2b, 0x96, 0xed
        },
        {
            0x86, 0x57, 0x1c, 0x92, 0x9d, 0x81, 0x4b, 0x06,
            0x3b, 0x22, 0xe6, 0x4c, 0x4b, 0x00, 0xa4, 0xb1
        },
        {
            0x1a, 0xc0, 0x68, 0xd5, 0x4d, 0x4b, 0x9a, 0xcd,
            0xd9, 0xa3, 0x4e, 0x32, 0xac, 0x0d, 0xb1, 0xe2
        },
        {
            0xd0, 0x0d, 0xf4, 0x65, 0xd5, 0x07, 0xa8, 0xc4,
            0x98, 0x4c, 0xdc, 0x2a, 0x06, 0x9c, 0xea, 0x76
        },
        {
            0xa7, 0x6d, 0xf8, 0x47, 0x6d, 0x71, 0xe3, 0xae,
            0x72, 0x14, 0x59, 0x07, 0x84, 0x2d, 0x83, 0xa4
        }
    
    };

    uint8_t key[SC2000_KEY_BYTES];
    uint8_t ciphertext[SC2000_BLOCK_BYTES];

    insecure_key_generate(key, sizeof(key));

    fputs("[\n", out);
    for (size_t i = 0; i < 5; i++) {
        memset(ciphertext, 0, sizeof(ciphertext));
        sc2000_enc(plaintexts[i], ciphertext, key);
        fprintf(out, "  {\n    \"plaintext\": \"");
        for (size_t j = 0; j < sizeof(plaintexts[i]); j++) fprintf(out, "%02x", plaintexts[i][j]);
        fprintf(out, "\",\n    \"key\": \"");
        for (size_t j = 0; j < sizeof(key); j++) fprintf(out, "%02x", key[j]);
        fprintf(out, "\",\n    \"iv\": \"\",\n    \"ciphertext\": \"");
        for (size_t j = 0; j < sizeof(ciphertext); j++) fprintf(out, "%02x", ciphertext[j]);
        fprintf(out, "\",\n    \"block_size\": 16\n  }%s\n", (i + 1 == 5) ? "" : ",");
    }
    fputs("]\n", out);
    return 0;
}

int main(int argc, char **argv) {
    FILE *out = stdout;
    if (argc >= 2) {
        out = fopen(argv[1], "w");
        if (!out) {
            perror("fopen");
            return 1;
        }
    }

    if (write_vectors(out) != 0) {
        if (out != stdout) fclose(out);
        return 1;
    }

    if (out != stdout) fclose(out);
    return 0;
}
