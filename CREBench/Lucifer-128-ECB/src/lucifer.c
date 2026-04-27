/*
 * LUCIFER Block Cipher Implementation
 * 
 * Based on Arthur Sorkin's CRYPTOLOGIA article (Volume 8, Number 1, January 1984)
 * and the reference implementations from lucifer-go and cryptospecs.
 * 
 * For educational and CTF purposes only.
 */

#include "lucifer.h"
#include <string.h>

#ifdef CONSTXOR_LUCIFER_TABLES
#include "constxor_tables.h"
#define LUCIFER_DPS (constxor_lucifer_dps())
#define LUCIFER_TCB0 (constxor_lucifer_tcb0())
#define LUCIFER_TCB1 (constxor_lucifer_tcb1())
#else
/*
 * Original S-boxes (for reference):
 * S0[16] = {12, 15, 7, 10, 14, 13, 11, 0, 2, 6, 3, 1, 9, 4, 5, 8};
 * S1[16] = {7, 2, 14, 9, 3, 11, 0, 4, 12, 13, 1, 10, 6, 15, 8, 5};
 * These are precomputed into TCB0 and TCB1 tables below for efficiency.
 */

/* Diffusion pattern schedule */
static const uint8_t Dps[64] = {
    4, 16, 32, 2, 1, 8, 64, 128,
    128, 4, 16, 32, 2, 1, 8, 64,
    64, 128, 4, 16, 32, 2, 1, 8,
    8, 64, 128, 4, 16, 32, 2, 1,
    1, 8, 64, 128, 4, 16, 32, 2,
    2, 1, 8, 64, 128, 4, 16, 32,
    32, 2, 1, 8, 64, 128, 4, 16,
    16, 32, 2, 1, 8, 64, 128, 4
};

/* Precomputed S&P Box (when TCB=0) */
static const uint8_t TCB0[256] = {
     87, 21,117, 54, 23, 55, 20, 84,116,118, 22, 53, 85,119, 52, 86,
    223,157,253,190,159,191,156,220,252,254,158,189,221,255,188,222,
    207,141,237,174,143,175,140,204,236,238,142,173,205,239,172,206,
    211,145,241,178,147,179,144,208,240,242,146,177,209,243,176,210,
    215,149,245,182,151,183,148,212,244,246,150,181,213,247,180,214,
     95, 29,125, 62, 31, 63, 28, 92,124,126, 30, 61, 93,127, 60, 94,
    219,153,249,186,155,187,152,216,248,250,154,185,217,251,184,218,
     67,  1, 97, 34,  3, 35,  0, 64, 96, 98,  2, 33, 65, 99, 32, 66,
    195,129,225,162,131,163,128,192,224,226,130,161,193,227,160,194,
    199,133,229,166,135,167,132,196,228,230,134,165,197,231,164,198,
    203,137,233,170,139,171,136,200,232,234,138,169,201,235,168,202,
     75,  9,105, 42, 11, 43,  8, 72,104,106, 10, 41, 73,107, 40, 74,
     91, 25,121, 58, 27, 59, 24, 88,120,122, 26, 57, 89,123, 56, 90,
     71,  5,101, 38,  7, 39,  4, 68,100,102,  6, 37, 69,103, 36, 70,
     79, 13,109, 46, 15, 47, 12, 76,108,110, 14, 45, 77,111, 44, 78,
     83, 17,113, 50, 19, 51, 16, 80,112,114, 18, 49, 81,115, 48, 82
};

/* Precomputed S&P Box (when TCB=1) */
static const uint8_t TCB1[256] = {
     87,223,207,211,215, 95,219, 67,195,199,203, 75, 91, 71, 79, 83,
     21,157,141,145,149, 29,153,  1,129,133,137,  9, 25,  5, 13, 17,
    117,253,237,241,245,125,249, 97,225,229,233,105,121,101,109,113,
     54,190,174,178,182, 62,186, 34,162,166,170, 42, 58, 38, 46, 50,
     23,159,143,147,151, 31,155,  3,131,135,139, 11, 27,  7, 15, 19,
     55,191,175,179,183, 63,187, 35,163,167,171, 43, 59, 39, 47, 51,
     20,156,140,144,148, 28,152,  0,128,132,136,  8, 24,  4, 12, 16,
     84,220,204,208,212, 92,216, 64,192,196,200, 72, 88, 68, 76, 80,
    116,252,236,240,244,124,248, 96,224,228,232,104,120,100,108,112,
    118,254,238,242,246,126,250, 98,226,230,234,106,122,102,110,114,
     22,158,142,146,150, 30,154,  2,130,134,138, 10, 26,  6, 14, 18,
     53,189,173,177,181, 61,185, 33,161,165,169, 41, 57, 37, 45, 49,
     85,221,205,209,213, 93,217, 65,193,197,201, 73, 89, 69, 77, 81,
    119,255,239,243,247,127,251, 99,227,231,235,107,123,103,111,115,
     52,188,172,176,180, 60,184, 32,160,164,168, 40, 56, 36, 44, 48,
     86,222,206,210,214, 94,218, 66,194,198,202, 74, 90, 70, 78, 82
};
#define LUCIFER_DPS (Dps)
#define LUCIFER_TCB0 (TCB0)
#define LUCIFER_TCB1 (TCB1)
#endif

/* Permutation table for key scheduling */
static const int P[8] = { 3, 5, 0, 4, 2, 1, 7, 6 };
static const int Smask[8] = { 128, 64, 32, 16, 8, 4, 2, 1 };

/* Load key and generate key schedule */
static void loadkey(lucifer_ctx *ctx, const uint8_t *keystr, int decrypt)
{
    uint8_t kk[16], pk[16];
    int kc, i, j;

    /* Process key bytes and create permuted key */
    for (i = 0; i < 16; i++) {
        kk[i] = keystr[i];
        pk[i] = 0;
        for (j = 0; j < 8; j++) {
            if (keystr[i] & Smask[j]) {
                pk[i] |= Smask[P[j]];
            }
        }
    }

    /* Generate key schedule based on encrypt/decrypt mode */
    kc = decrypt ? 8 : 0;
    for (i = 0; i < 16; i++) {
        if (decrypt) {
            kc = (kc + 1) & 0x0f;
        }
        ctx->key[i] = kk[kc];
        for (j = 0; j < 8; j++) {
            ctx->pkey[i * 8 + j] = pk[kc];
            if (j < 7 || decrypt) {
                kc = (kc + 1) & 0x0f;
            }
        }
    }

    ctx->is_decrypt = decrypt;
}

void lucifer_set_encrypt_key(lucifer_ctx *ctx, const uint8_t *key)
{
    loadkey(ctx, key, 0);
}

void lucifer_set_decrypt_key(lucifer_ctx *ctx, const uint8_t *key)
{
    loadkey(ctx, key, 1);
}

/* Core LUCIFER block cipher function */
static void lucifer_block(lucifer_ctx *ctx, uint8_t *block)
{
    uint8_t *h0, *h1;
    const uint8_t *kc, *ks;
    const uint8_t *dp;
    int tcb, val, i, j;
    uint8_t *cp, temp;

    h0 = &block[0];     /* lower half */
    h1 = &block[8];     /* upper half */
    kc = ctx->pkey;
    ks = ctx->key;

    for (i = 0; i < LUCIFER_ROUNDS; i++) {
        tcb = *ks++;
        dp = LUCIFER_DPS;

        for (j = 0; j < 8; j++) {
            /* Select TCB based on key bit */
            if (tcb & Smask[j]) {
                val = LUCIFER_TCB1[h1[j]];
            } else {
                val = LUCIFER_TCB0[h1[j]];
            }
            val ^= *kc++;

            /* Apply diffusion to lower half */
            for (cp = h0; cp < h0 + 8; cp++) {
                *cp ^= (val & *dp++);
            }
        }

        /* Swap halves (virtual) */
        cp = h0;
        h0 = h1;
        h1 = cp;
    }

    /* Actually swap the halves */
    for (i = 0; i < 8; i++) {
        temp = block[i];
        block[i] = block[i + 8];
        block[i + 8] = temp;
    }
}

void lucifer_encrypt_block(lucifer_ctx *ctx, const uint8_t *in, uint8_t *out)
{
    memcpy(out, in, LUCIFER_BLOCK_SIZE);
    lucifer_block(ctx, out);
}

void lucifer_decrypt_block(lucifer_ctx *ctx, const uint8_t *in, uint8_t *out)
{
    memcpy(out, in, LUCIFER_BLOCK_SIZE);
    lucifer_block(ctx, out);
}

void lucifer_ecb_encrypt(lucifer_ctx *ctx, const uint8_t *in, uint8_t *out, size_t len)
{
    size_t i;
    for (i = 0; i < len; i += LUCIFER_BLOCK_SIZE) {
        lucifer_encrypt_block(ctx, in + i, out + i);
    }
}

void lucifer_ecb_decrypt(lucifer_ctx *ctx, const uint8_t *in, uint8_t *out, size_t len)
{
    size_t i;
    for (i = 0; i < len; i += LUCIFER_BLOCK_SIZE) {
        lucifer_decrypt_block(ctx, in + i, out + i);
    }
}
