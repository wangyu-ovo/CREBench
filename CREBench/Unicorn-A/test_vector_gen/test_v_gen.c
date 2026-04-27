#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/unicorn-a.h"

extern void insecure_key_generate(uint8_t *key, size_t key_len);

static int write_vectors(FILE *out) {
    static const uint8_t plaintexts[5][UNICORN_BLOCK_BYTES] = {
        {
            0xe5, 0xb6, 0xe8, 0xbd, 0x87, 0x7a, 0xe3, 0x60,
            0x79, 0x96, 0x2a, 0xc7, 0x95, 0x2e, 0x18, 0x23
        },
        {
            0xca, 0x7c, 0x2b, 0xda, 0x23, 0x1f, 0xe3, 0xe7,
            0xf6, 0x30, 0xe9, 0x3a, 0x57, 0x3b, 0xe7, 0xa8
        },
        {
            0xc3, 0xee, 0xd4, 0xcc, 0xee, 0x37, 0xee, 0xd3,
            0x85, 0x95, 0x21, 0x8e, 0x83, 0x48, 0x1a, 0xa6
        },
        {
            0x5c, 0x60, 0x4a, 0xf5, 0x1a, 0xef, 0xa6, 0xbb,
            0x6f, 0x3d, 0x3f, 0x9c, 0x4a, 0xa5, 0x39, 0x5c
        },
        {
            0x5a, 0xb5, 0x17, 0x9d, 0x64, 0xfe, 0x65, 0xbb,
            0xd5, 0x4a, 0x53, 0xe2, 0x29, 0x02, 0x75, 0x9d
        }
    
    };

    uint8_t key[UNICORN_KEY_BYTES];
    uint8_t ciphertext[UNICORN_BLOCK_BYTES];

    insecure_key_generate(key, sizeof(key));

    fputs("[\n", out);
    for (size_t i = 0; i < 5; i++) {
        memset(ciphertext, 0, sizeof(ciphertext));
        unicorn_enc(plaintexts[i], ciphertext, key);
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
