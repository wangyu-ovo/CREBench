#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/tea.h"

extern void insecure_key_generate(uint8_t *key, size_t key_len);

static int write_vectors(FILE *out) {
    static const uint8_t plaintexts[5][TEA_BLOCK_BYTES] = {
        {
            0x63, 0xc0, 0x45, 0x5a, 0x63, 0xf6, 0x07, 0x27
        },
        {
            0x2c, 0x78, 0x76, 0xc2, 0x73, 0x40, 0xb4, 0x47
        },
        {
            0x7a, 0x78, 0xae, 0x26, 0xcd, 0x9f, 0x7c, 0xc2
        },
        {
            0x67, 0xca, 0x51, 0x79, 0x9e, 0xfd, 0xef, 0x89
        },
        {
            0xad, 0x97, 0x8e, 0xf5, 0x6f, 0x2d, 0x19, 0xe1
        }
    
    };

    uint8_t key[TEA_KEY_BYTES];
    uint8_t ciphertext[TEA_BLOCK_BYTES];

    insecure_key_generate(key, sizeof(key));

    fputs("[\n", out);
    for (size_t i = 0; i < 5; i++) {
        memset(ciphertext, 0, sizeof(ciphertext));
        tea_enc(plaintexts[i], ciphertext, key);
        fprintf(out, "  {\n    \"plaintext\": \"");
        for (size_t j = 0; j < sizeof(plaintexts[i]); j++) fprintf(out, "%02x", plaintexts[i][j]);
        fprintf(out, "\",\n    \"key\": \"");
        for (size_t j = 0; j < sizeof(key); j++) fprintf(out, "%02x", key[j]);
        fprintf(out, "\",\n    \"iv\": \"\",\n    \"ciphertext\": \"");
        for (size_t j = 0; j < sizeof(ciphertext); j++) fprintf(out, "%02x", ciphertext[j]);
        fprintf(out, "\",\n    \"block_size\": 8\n  }%s\n", (i + 1 == 5) ? "" : ",");
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
