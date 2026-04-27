#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/rc2.h"

extern void insecure_key_generate(uint8_t *key, size_t key_len);

static int write_vectors(FILE *out) {
    static const uint8_t iv[RC2_BLOCK_BYTES] = {
        0xaf, 0x55, 0xd4, 0x8b, 0xb3, 0xf4, 0x2f, 0x5b
    };
    static const uint8_t plaintexts[5][16] = {
        {
            0x78, 0x30, 0x9f, 0x62, 0xf0, 0x5d, 0xac, 0x23,
            0x20, 0x32, 0x99, 0x8d, 0x74, 0xe4, 0xc8, 0xc5
        },
        {
            0x82, 0xe3, 0x97, 0xf0, 0x95, 0xf3, 0xc9, 0xc9,
            0x83, 0x95, 0xbe, 0x81, 0xae, 0xcc, 0xec, 0x79
        },
        {
            0x6d, 0x3a, 0xb7, 0xef, 0x83, 0xda, 0x26, 0x85,
            0x0e, 0xa1, 0x19, 0x47, 0x9e, 0x31, 0x38, 0xb9
        },
        {
            0x76, 0xf7, 0xab, 0x09, 0x36, 0x17, 0x28, 0x3f,
            0xcf, 0x1c, 0x7e, 0x7a, 0xb6, 0x77, 0x8e, 0x0e
        },
        {
            0x7d, 0x67, 0x18, 0x60, 0x1d, 0x2b, 0x08, 0xa7,
            0x3d, 0xbe, 0xc7, 0xdf, 0x3f, 0xd5, 0xbf, 0xef
        }
    
    };

    uint8_t key[8];
    uint8_t ciphertext[16];
    rc2_ctx ctx;

    insecure_key_generate(key, sizeof(key));
    rc2_key_set(&ctx, key, sizeof(key));

    fputs("[\n", out);
    for (size_t i = 0; i < 5; i++) {
        memset(ciphertext, 0, sizeof(ciphertext));
        rc2_cbc_encrypt(&ctx, iv, plaintexts[i], ciphertext, sizeof(ciphertext));
        fprintf(out, "  {\n    \"plaintext\": \"");
        for (size_t j = 0; j < sizeof(plaintexts[i]); j++) fprintf(out, "%02x", plaintexts[i][j]);
        fprintf(out, "\",\n    \"key\": \"");
        for (size_t j = 0; j < sizeof(key); j++) fprintf(out, "%02x", key[j]);
        fprintf(out, "\",\n    \"iv\": \"");
        for (size_t j = 0; j < sizeof(iv); j++) fprintf(out, "%02x", iv[j]);
        fprintf(out, "\",\n    \"ciphertext\": \"");
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
