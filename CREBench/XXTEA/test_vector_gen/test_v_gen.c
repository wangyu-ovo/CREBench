#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/xxtea.h"

extern void insecure_key_generate(uint8_t *key, size_t key_len);

static int write_vectors(FILE *out) {
    static const uint8_t plaintexts[5][XXTEA_BLOCK_BYTES] = {
        {
            0x7d, 0x15, 0x42, 0xf9, 0xc5, 0x29, 0x09, 0x54,
            0x72, 0xfe, 0xbe, 0xfc, 0x68, 0x73, 0xda, 0x7c
        },
        {
            0xfe, 0x20, 0x73, 0xe3, 0x84, 0xeb, 0x04, 0x74,
            0xa5, 0x21, 0xd3, 0x3a, 0x28, 0xae, 0x94, 0xe7
        },
        {
            0xa8, 0xc5, 0x7c, 0x02, 0x0d, 0x85, 0x66, 0x69,
            0x30, 0x09, 0xfe, 0xcb, 0x19, 0x70, 0x10, 0x34
        },
        {
            0x51, 0xea, 0xc0, 0xc7, 0xa7, 0x27, 0x8e, 0x8c,
            0x59, 0xd1, 0xd1, 0xd1, 0xe3, 0x26, 0x2b, 0xb9
        },
        {
            0x55, 0x80, 0x3f, 0x22, 0x5b, 0xf1, 0xf0, 0xa4,
            0x1f, 0xe5, 0x52, 0x7d, 0x53, 0x66, 0x47, 0x7a
        }
    
    };

    uint8_t key[XXTEA_KEY_BYTES];
    uint8_t ciphertext[XXTEA_BLOCK_BYTES];

    insecure_key_generate(key, sizeof(key));

    fputs("[\n", out);
    for (size_t i = 0; i < 5; i++) {
        memset(ciphertext, 0, sizeof(ciphertext));
        xxtea_enc(plaintexts[i], ciphertext, key);
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
