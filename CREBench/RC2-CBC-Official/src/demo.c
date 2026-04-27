#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rc2.h>
#include <openssl/provider.h>
#include "rc2.h"

static int hex_char_to_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex(const char *hex, unsigned char *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return 0;
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_char_to_nibble(hex[2 * i]);
        int lo = hex_char_to_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

static void print_hex(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <32-hex-chars>\n", argv[0]);
        return 1;
    }

    /* RC2 key (16 bytes, 128 effective bits) and IV (8 bytes) */
    const unsigned char key[16] = {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01
    };
    const unsigned char iv_init[RC2_BLOCK_BYTES] = { 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };

    unsigned char plaintext[16]; /* 2 blocks */
    if (!parse_hex(argv[1], plaintext, sizeof(plaintext))) {
        fprintf(stderr, "Bad input hex. Expecting 32 hex chars (16 bytes).\n");
        return 1;
    }

    /* Our RC2 CBC */
    rc2_ctx ctx;
    rc2_key_set(&ctx, key, sizeof(key));
    unsigned char ct_mine[sizeof(plaintext)];
    rc2_cbc_encrypt(&ctx, iv_init, plaintext, ct_mine, sizeof(ct_mine));

    /* Load providers for OpenSSL 3.x */
    OSSL_PROVIDER *deflt = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");

    /* OpenSSL RC2-CBC via EVP (no padding) */
    unsigned char iv2[RC2_BLOCK_BYTES];
    memcpy(iv2, iv_init, RC2_BLOCK_BYTES);
    unsigned char ct_ossl[sizeof(plaintext)];
    int outlen = 0, finallen = 0;
    EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();
    if (!ectx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        if (legacy) OSSL_PROVIDER_unload(legacy);
        if (deflt) OSSL_PROVIDER_unload(deflt);
        return 2;
    }
    if (EVP_EncryptInit_ex(ectx, EVP_rc2_cbc(), NULL, key, iv2) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex failed (RC2 may require legacy provider)\n");
        EVP_CIPHER_CTX_free(ectx);
        if (legacy) OSSL_PROVIDER_unload(legacy);
        if (deflt) OSSL_PROVIDER_unload(deflt);
        return 2;
    }
    /* Ensure effective key bits match */
    if (EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_SET_RC2_KEY_BITS, 128, NULL) != 1) {
        fprintf(stderr, "EVP_CIPHER_CTX_ctrl EVP_CTRL_SET_RC2_KEY_BITS failed\n");
        EVP_CIPHER_CTX_free(ectx);
        if (legacy) OSSL_PROVIDER_unload(legacy);
        if (deflt) OSSL_PROVIDER_unload(deflt);
        return 2;
    }
    EVP_CIPHER_CTX_set_padding(ectx, 0);
    if (EVP_EncryptUpdate(ectx, ct_ossl, &outlen, plaintext, (int)sizeof(plaintext)) != 1) {
        fprintf(stderr, "EVP_EncryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ectx);
        if (legacy) OSSL_PROVIDER_unload(legacy);
        if (deflt) OSSL_PROVIDER_unload(deflt);
        return 2;
    }
    if (EVP_EncryptFinal_ex(ectx, ct_ossl + outlen, &finallen) != 1) {
        fprintf(stderr, "EVP_EncryptFinal_ex failed\n");
        EVP_CIPHER_CTX_free(ectx);
        if (legacy) OSSL_PROVIDER_unload(legacy);
        if (deflt) OSSL_PROVIDER_unload(deflt);
        return 2;
    }
    EVP_CIPHER_CTX_free(ectx);

    size_t total = (size_t)(outlen + finallen);
    if (total != sizeof(plaintext)) {
        fprintf(stderr, "Unexpected EVP output length: %zu\n", total);
        if (legacy) OSSL_PROVIDER_unload(legacy);
        if (deflt) OSSL_PROVIDER_unload(deflt);
        return 2;
    }

    printf("Plaintext (hex): ");
    print_hex(plaintext, sizeof(plaintext));
    printf("\n");
    printf("Ciphertext MyRC2 (hex): ");
    print_hex(ct_mine, sizeof(ct_mine));
    printf("\n");
    printf("Ciphertext OpenSSL (hex): ");
    print_hex(ct_ossl, sizeof(ct_ossl));
    printf("\n");

    int same = memcmp(ct_mine, ct_ossl, sizeof(ct_mine)) == 0;
    printf("Match: %s\n", same ? "True" : "False");

    if (legacy) OSSL_PROVIDER_unload(legacy);
    if (deflt) OSSL_PROVIDER_unload(deflt);
    return same ? 0 : 2;
}
