#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/seed.h"

extern void insecure_key_generate(uint8_t *key, size_t key_len);

static int write_vectors(FILE *out) {
    static const uint8_t plaintexts[5][SEED_BLOCK_BYTES] = {
        {
            0x64, 0x1d, 0xcc, 0xf9, 0x09, 0xf4, 0x4d, 0x59,
            0x3b, 0xdc, 0xd3, 0x5a, 0xe8, 0x9c, 0xe6, 0x32
        },
        {
            0x3d, 0x36, 0x1b, 0x47, 0x72, 0x2b, 0x1f, 0x04,
            0xef, 0x43, 0xa1, 0x91, 0xe1, 0x13, 0x57, 0x3b
        },
        {
            0x9d, 0x6b, 0x79, 0xc3, 0x18, 0x08, 0x5d, 0x8e,
            0xf4, 0x02, 0x2a, 0x43, 0x10, 0x01, 0x80, 0x0c
        },
        {
            0xe7, 0xd6, 0x08, 0x67, 0x84, 0x51, 0xcd, 0xf0,
            0xeb, 0x71, 0x17, 0x95, 0xfa, 0x5e, 0x34, 0x4d
        },
        {
            0xb8, 0xb9, 0xea, 0x69, 0xd4, 0x25, 0xf9, 0x5c,
            0xd4, 0x06, 0xe5, 0x37, 0xfe, 0x56, 0xaa, 0x58
        }
    
    };

    uint8_t key[SEED_KEY_BYTES];
    uint8_t ciphertext[SEED_BLOCK_BYTES];

    insecure_key_generate(key, sizeof(key));

    fputs("[\n", out);
    for (size_t i = 0; i < 5; i++) {
        memset(ciphertext, 0, sizeof(ciphertext));
        seed_enc(plaintexts[i], ciphertext, key);
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
