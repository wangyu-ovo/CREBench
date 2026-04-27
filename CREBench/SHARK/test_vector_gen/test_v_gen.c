#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/shark.h"

extern void insecure_key_generate(uint8_t *key, size_t key_len);

static int write_vectors(FILE *out) {
    static const uint8_t plaintexts[5][SHARK_BLOCK_BYTES] = {
        {
            0x98, 0x27, 0x00, 0xc1, 0x97, 0xd5, 0x80, 0x57
        },
        {
            0x44, 0xc5, 0x27, 0x69, 0xae, 0xfa, 0x3d, 0x2e
        },
        {
            0x6c, 0x36, 0x03, 0x91, 0xcb, 0x3b, 0x43, 0x00
        },
        {
            0x40, 0x32, 0x24, 0xe7, 0xeb, 0xa9, 0x10, 0xdf
        },
        {
            0x9f, 0xd3, 0xf2, 0x95, 0x4a, 0xf4, 0x1f, 0x06
        }
    
    };

    uint8_t key[SHARK_KEY_BYTES];
    uint8_t ciphertext[SHARK_BLOCK_BYTES];

    insecure_key_generate(key, sizeof(key));

    fputs("[\n", out);
    for (size_t i = 0; i < 5; i++) {
        memset(ciphertext, 0, sizeof(ciphertext));
        shark_enc(plaintexts[i], ciphertext, key);
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
