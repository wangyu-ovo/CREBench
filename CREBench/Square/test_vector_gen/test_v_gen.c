#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/square.h"

extern void insecure_key_generate(uint8_t *key, size_t key_len);

static int write_vectors(FILE *out) {
    static const uint8_t plaintexts[5][SQUARE_BLOCK_BYTES] = {
        {
            0x1a, 0xfc, 0xce, 0x7e, 0x2e, 0xd1, 0x4b, 0xc7,
            0x7c, 0xdd, 0x74, 0xa9, 0xaf, 0x92, 0x68, 0x9f
        },
        {
            0x54, 0xca, 0x78, 0xda, 0x39, 0x37, 0x46, 0x30,
            0x67, 0xd0, 0x05, 0xbc, 0x67, 0xdc, 0xa9, 0x9a
        },
        {
            0x24, 0xaf, 0xdd, 0x91, 0x5f, 0x6a, 0xf4, 0xf2,
            0xdd, 0x53, 0xb9, 0x13, 0xf3, 0x3e, 0x34, 0xd4
        },
        {
            0x7f, 0xec, 0xc3, 0xb9, 0x19, 0x07, 0x3e, 0x68,
            0x7b, 0xc2, 0x72, 0xcd, 0x32, 0xeb, 0x60, 0x8d
        },
        {
            0x93, 0x7e, 0xd9, 0x4a, 0x75, 0xe4, 0x46, 0x91,
            0x91, 0x74, 0xef, 0x1f, 0x98, 0xf4, 0x80, 0x8b
        }
    
    };

    uint8_t key[SQUARE_KEY_BYTES];
    uint8_t ciphertext[SQUARE_BLOCK_BYTES];

    insecure_key_generate(key, sizeof(key));

    fputs("[\n", out);
    for (size_t i = 0; i < 5; i++) {
        memset(ciphertext, 0, sizeof(ciphertext));
        square_enc(plaintexts[i], ciphertext, key);
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
