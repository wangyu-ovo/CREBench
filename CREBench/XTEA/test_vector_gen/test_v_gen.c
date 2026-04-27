#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/xtea.h"

extern void insecure_key_generate(uint8_t *key, size_t key_len);

static int write_vectors(FILE *out) {
    static const uint8_t plaintexts[5][XTEA_BLOCK_BYTES] = {
        {
            0xc5, 0x99, 0x43, 0xfe, 0x85, 0x7e, 0x33, 0xde
        },
        {
            0x50, 0xb0, 0x55, 0xe2, 0x41, 0x35, 0xc7, 0xc2
        },
        {
            0x26, 0xe1, 0xb4, 0x9d, 0x43, 0xe6, 0x40, 0x31
        },
        {
            0x88, 0x5d, 0x2c, 0x7d, 0xf5, 0x0f, 0xef, 0xc1
        },
        {
            0xee, 0x22, 0x15, 0x48, 0xfe, 0x4c, 0x16, 0xdc
        }
    
    };

    uint8_t key[XTEA_KEY_BYTES];
    uint8_t ciphertext[XTEA_BLOCK_BYTES];

    insecure_key_generate(key, sizeof(key));

    fputs("[\n", out);
    for (size_t i = 0; i < 5; i++) {
        memset(ciphertext, 0, sizeof(ciphertext));
        xtea_enc(plaintexts[i], ciphertext, key);
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
