#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/simon.h"

extern void insecure_key_generate(uint8_t *key, size_t key_len);

static int write_vectors(FILE *out) {
    static const uint8_t plaintexts[5][SIMON_BLOCK_BYTES] = {
        {
            0x3f, 0x39, 0x19, 0x4d, 0xf1, 0x0c, 0x9d, 0x5b
        },
        {
            0x44, 0x9c, 0x7c, 0x32, 0x32, 0x03, 0x31, 0x68
        },
        {
            0x51, 0x54, 0x4c, 0x75, 0xec, 0x97, 0xd2, 0x01
        },
        {
            0xf5, 0x30, 0x94, 0xf1, 0x95, 0x43, 0x37, 0xed
        },
        {
            0x53, 0x01, 0xb7, 0x13, 0x73, 0x38, 0x69, 0x2e
        }
    
    };

    uint8_t key[SIMON_KEY_BYTES];
    uint8_t ciphertext[SIMON_BLOCK_BYTES];

    insecure_key_generate(key, sizeof(key));

    fputs("[\n", out);
    for (size_t i = 0; i < 5; i++) {
        memset(ciphertext, 0, sizeof(ciphertext));
        simon_enc(plaintexts[i], ciphertext, key);
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
