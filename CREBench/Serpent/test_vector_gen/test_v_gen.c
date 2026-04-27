#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/serpent.h"

extern void insecure_key_generate(uint8_t *key, size_t key_len);

static int write_vectors(FILE *out) {
    static const uint8_t plaintexts[5][SERPENT_BLOCK_BYTES] = {
        {
            0xec, 0x4b, 0x46, 0xae, 0x32, 0x3c, 0xec, 0x71,
            0xf6, 0x59, 0xc9, 0x34, 0xbd, 0x7d, 0x22, 0xfa
        },
        {
            0xea, 0x39, 0xa9, 0x1c, 0xc5, 0x5c, 0x1d, 0xd4,
            0x20, 0x3f, 0xef, 0xa5, 0xf9, 0x2f, 0x8a, 0xf3
        },
        {
            0x4a, 0xb3, 0x7d, 0x60, 0x33, 0x70, 0x7b, 0x92,
            0x3d, 0x1d, 0x2a, 0x09, 0xd1, 0x14, 0x30, 0x44
        },
        {
            0x35, 0xac, 0xbe, 0xac, 0xc1, 0x60, 0xd7, 0x26,
            0x49, 0xcc, 0xc0, 0x17, 0xdf, 0x77, 0x22, 0x17
        },
        {
            0xc6, 0x6f, 0xfe, 0xcf, 0x09, 0xc0, 0x86, 0x6d,
            0x55, 0xd1, 0xc1, 0x10, 0x91, 0xa9, 0x02, 0xc2
        }
    
    };

    uint8_t key[SERPENT_KEY_BYTES];
    uint8_t ciphertext[SERPENT_BLOCK_BYTES];

    insecure_key_generate(key, sizeof(key));

    fputs("[\n", out);
    for (size_t i = 0; i < 5; i++) {
        memset(ciphertext, 0, sizeof(ciphertext));
        serpent_enc(plaintexts[i], ciphertext, key);
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
