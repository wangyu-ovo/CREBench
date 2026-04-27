#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/speck.h"

extern void insecure_key_generate(uint8_t *key, size_t key_len);

static int write_vectors(FILE *out) {
    static const uint8_t plaintexts[5][SPECK_BLOCK_BYTES] = {
        {
            0x34, 0xbf, 0x90, 0xfd, 0xec, 0x2c, 0x6e, 0x3a
        },
        {
            0xbf, 0x9b, 0xcf, 0xe5, 0x59, 0x20, 0xa2, 0x96
        },
        {
            0x83, 0x6e, 0xf1, 0x6a, 0x19, 0xb5, 0xca, 0xae
        },
        {
            0xe1, 0x9d, 0xa7, 0x50, 0x76, 0x17, 0x7c, 0xa8
        },
        {
            0x81, 0x32, 0x2c, 0xcb, 0x14, 0x4f, 0xda, 0x59
        }
    
    };

    uint8_t key[SPECK_KEY_BYTES];
    uint8_t ciphertext[SPECK_BLOCK_BYTES];

    insecure_key_generate(key, sizeof(key));

    fputs("[\n", out);
    for (size_t i = 0; i < 5; i++) {
        memset(ciphertext, 0, sizeof(ciphertext));
        speck_enc(plaintexts[i], ciphertext, key);
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
