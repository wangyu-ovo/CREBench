/* camellia.h - Simplified Camellia 128-bit encryption header
 * Based on RFC 3713 and implementation from Yuichi Kobayashi <kobayasy@kobayasy.com>
 *
 * Simplified for 128-bit encryption only
 */

#include <stddef.h>
#include <stdint.h>
#include "camellia.h"

#ifndef ASSERT
#include <assert.h>
#define ASSERT(_test) assert(_test)
#endif  /* #ifndef ASSERT */

/* Convert big-endian 8-byte data */
#define n8u64(_n64) \
    ((uint64_t)((uint8_t *)(_n64))[0] << 56 | \
     (uint64_t)((uint8_t *)(_n64))[1] << 48 | \
     (uint64_t)((uint8_t *)(_n64))[2] << 40 | \
     (uint64_t)((uint8_t *)(_n64))[3] << 32 | \
     (uint64_t)((uint8_t *)(_n64))[4] << 24 | \
     (uint64_t)((uint8_t *)(_n64))[5] << 16 | \
     (uint64_t)((uint8_t *)(_n64))[6] <<  8 | \
     (uint64_t)((uint8_t *)(_n64))[7] <<  0 )

/* Convert to big-endian 8-byte data */
#define u8n64_set(_u64, _n64) \
    do { \
        ((uint8_t *)(_n64))[0] = (uint8_t)((uint64_t)(_u64) >> 56); \
        ((uint8_t *)(_n64))[1] = (uint8_t)((uint64_t)(_u64) >> 48); \
        ((uint8_t *)(_n64))[2] = (uint8_t)((uint64_t)(_u64) >> 40); \
        ((uint8_t *)(_n64))[3] = (uint8_t)((uint64_t)(_u64) >> 32); \
        ((uint8_t *)(_n64))[4] = (uint8_t)((uint64_t)(_u64) >> 24); \
        ((uint8_t *)(_n64))[5] = (uint8_t)((uint64_t)(_u64) >> 16); \
        ((uint8_t *)(_n64))[6] = (uint8_t)((uint64_t)(_u64) >>  8); \
        ((uint8_t *)(_n64))[7] = (uint8_t)((uint64_t)(_u64) >>  0); \
    } while (0)

/* 64-bit value swap */
#define s64(_n1, _n2) \
    do { \
        register uint64_t d; \
        d = (_n1), (_n1) = (_n2), (_n2) = d; \
    } while (0)

/* 8-bit left rotation */
static inline uint8_t r8(uint8_t dataIn, uint8_t bit) {
    uint8_t dataOut;
    uint8_t bit1, bit2;

    bit1 = bit & 0x07, bit2 = 0x08 - bit1;
    dataOut = bit1 > 0 ? dataIn << bit1 | dataIn >> bit2 : dataIn;
    return dataOut;
}

/* 32-bit left rotation */
static inline uint32_t r32(uint32_t dataIn, uint8_t bit) {
    uint32_t dataOut;
    uint32_t bit1, bit2;

    bit1 = bit & 0x1f, bit2 = 0x20 - bit1;
    dataOut = bit1 > 0 ? dataIn << bit1 | dataIn >> bit2 : dataIn;
    return dataOut;
}

/* 128-bit left rotation */
static void r128(const uint64_t *dataIn, uint8_t bit,
                 uint64_t *dataOutH, uint64_t *dataOutL) {
    uint8_t bit1, bit2, bit3;
    uint64_t dataH, dataL;

    bit1 = bit & 0x3f, bit2 = 0x40 - bit1, bit3 = bit & 0x40;
    if (bit1 > 0) {
        dataH = dataIn[0] << bit1 | dataIn[1] >> bit2;
        dataL = dataIn[1] << bit1 | dataIn[0] >> bit2;
    }
    else {
        dataH = dataIn[0];
        dataL = dataIn[1];
    }
    switch (bit3) {
    case 0x00:
        break;
    case 0x40:
        s64(dataH, dataL);
        break;
    default:
        ASSERT(0);  /* never reached */
    }
    if (dataOutH != NULL)
        *dataOutH = dataH;
    if (dataOutL != NULL)
        *dataOutL = dataL;
}

/* Constants and S-boxes as per RFC 3713 */
#ifdef CONSTXOR_CAMELLIA_TABLES
#include "constxor_tables.h"
#define CAMELLIA_SIGMA1_VALUE (constxor_camellia_sigma1()[0])
#define CAMELLIA_SIGMA2_VALUE (constxor_camellia_sigma2()[0])
#define CAMELLIA_SIGMA3_VALUE (constxor_camellia_sigma3()[0])
#define CAMELLIA_SIGMA4_VALUE (constxor_camellia_sigma4()[0])
#define CAMELLIA_SBOX1_TABLE (constxor_camellia_sbox1())
#define CAMELLIA_SBOX2_TABLE (constxor_camellia_sbox2())
#define CAMELLIA_SBOX3_TABLE (constxor_camellia_sbox3())
#define CAMELLIA_SBOX4_TABLE (constxor_camellia_sbox4())
#else
static const struct {
    uint64_t sigma1, sigma2, sigma3, sigma4;
    uint8_t sbox1[256], sbox2[256], sbox3[256], sbox4[256];
} camellia = {
    .sigma1 = 0xa09e667f3bcc908b,
    .sigma2 = 0xb67ae8584caa73b2,
    .sigma3 = 0xc6ef372fe94f82be,
    .sigma4 = 0x54ff53a5f1d36f1c,
    .sbox1 = {
        112, 130,  44, 236, 179,  39, 192, 229, 228, 133,  87,  53, 234,  12, 174,  65,
         35, 239, 107, 147,  69,  25, 165,  33, 237,  14,  79,  78,  29, 101, 146, 189,
        134, 184, 175, 143, 124, 235,  31, 206,  62,  48, 220,  95,  94, 197,  11,  26,
        166, 225,  57, 202, 213,  71,  93,  61, 217,   1,  90, 214,  81,  86, 108,  77,
        139,  13, 154, 102, 251, 204, 176,  45, 116,  18,  43,  32, 240, 177, 132, 153,
        223,  76, 203, 194,  52, 126, 118,   5, 109, 183, 169,  49, 209,  23,   4, 215,
         20,  88,  58,  97, 222,  27,  17,  28,  50,  15, 156,  22,  83,  24, 242,  34,
        254,  68, 207, 178, 195, 181, 122, 145,  36,   8, 232, 168,  96, 252, 105,  80,
        170, 208, 160, 125, 161, 137,  98, 151,  84,  91,  30, 149, 224, 255, 100, 210,
         16, 196,   0,  72, 163, 247, 117, 219, 138,   3, 230, 218,   9,  63, 221, 148,
        135,  92, 131,   2, 205,  74, 144,  51, 115, 103, 246, 243, 157, 127, 191, 226,
         82, 155, 216,  38, 200,  55, 198,  59, 129, 150, 111,  75,  19, 190,  99,  46,
        233, 121, 167, 140, 159, 110, 188, 142,  41, 245, 249, 182,  47, 253, 180,  89,
        120, 152,   6, 106, 231,  70, 113, 186, 212,  37, 171,  66, 136, 162, 141, 250,
        114,   7, 185,  85, 248, 238, 172,  10,  54,  73,  42, 104,  60,  56, 241, 164,
         64,  40, 211, 123, 187, 201,  67, 193,  21, 227, 173, 244, 119, 199, 128, 158
    },
    .sbox2 = {
        224,   5,  88, 217, 103,  78, 129, 203, 201,  11, 174, 106, 213,  24,  93, 130,
         70, 223, 214,  39, 138,  50,  75,  66, 219,  28, 158, 156,  58, 202,  37, 123,
         13, 113,  95,  31, 248, 215,  62, 157, 124,  96, 185, 190, 188, 139,  22,  52,
         77, 195, 114, 149, 171, 142, 186, 122, 179,   2, 180, 173, 162, 172, 216, 154,
         23,  26,  53, 204, 247, 153,  97,  90, 232,  36,  86,  64, 225,  99,   9,  51,
        191, 152, 151, 133, 104, 252, 236,  10, 218, 111,  83,  98, 163,  46,   8, 175,
         40, 176, 116, 194, 189,  54,  34,  56, 100,  30,  57,  44, 166,  48, 229,  68,
        253, 136, 159, 101, 135, 107, 244,  35,  72,  16, 209,  81, 192, 249, 210, 160,
         85, 161,  65, 250,  67,  19, 196,  47, 168, 182,  60,  43, 193, 255, 200, 165,
         32, 137,   0, 144,  71, 239, 234, 183,  21,   6, 205, 181,  18, 126, 187,  41,
         15, 184,   7,   4, 155, 148,  33, 102, 230, 206, 237, 231,  59, 254, 127, 197,
        164,  55, 177,  76, 145, 110, 141, 118,   3,  45, 222, 150,  38, 125, 198,  92,
        211, 242,  79,  25,  63, 220, 121,  29,  82, 235, 243, 109,  94, 251, 105, 178,
        240,  49,  12, 212, 207, 140, 226, 117, 169,  74,  87, 132,  17,  69,  27, 245,
        228,  14, 115, 170, 241, 221,  89,  20, 108, 146,  84, 208, 120, 112, 227,  73,
        128,  80, 167, 246, 119, 147, 134, 131,  42, 199,  91, 233, 238, 143,   1,  61
    },
    .sbox3 = {
         56,  65,  22, 118, 217, 147,  96, 242, 114, 194, 171, 154, 117,   6,  87, 160,
        145, 247, 181, 201, 162, 140, 210, 144, 246,   7, 167,  39, 142, 178,  73, 222,
         67,  92, 215, 199,  62, 245, 143, 103,  31,  24, 110, 175,  47, 226, 133,  13,
         83, 240, 156, 101, 234, 163, 174, 158, 236, 128,  45, 107, 168,  43,  54, 166,
        197, 134,  77,  51, 253, 102,  88, 150,  58,   9, 149,  16, 120, 216,  66, 204,
        239,  38, 229,  97,  26,  63,  59, 130, 182, 219, 212, 152, 232, 139,   2, 235,
         10,  44,  29, 176, 111, 141, 136,  14,  25, 135,  78,  11, 169,  12, 121,  17,
        127,  34, 231,  89, 225, 218,  61, 200,  18,   4, 116,  84,  48, 126, 180,  40,
         85, 104,  80, 190, 208, 196,  49, 203,  42, 173,  15, 202, 112, 255,  50, 105,
          8,  98,   0,  36, 209, 251, 186, 237,  69, 129, 115, 109, 132, 159, 238,  74,
        195,  46, 193,   1, 230,  37,  72, 153, 185, 179, 123, 249, 206, 191, 223, 113,
         41, 205, 108,  19, 100, 155,  99, 157, 192,  75, 183, 165, 137,  95, 177,  23,
        244, 188, 211,  70, 207,  55,  94,  71, 148, 250, 252,  91, 151, 254,  90, 172,
         60,  76,   3,  53, 243,  35, 184,  93, 106, 146, 213,  33,  68,  81, 198, 125,
         57, 131, 220, 170, 124, 119,  86,   5,  27, 164,  21,  52,  30,  28, 248,  82,
         32,  20, 233, 189, 221, 228, 161, 224, 138, 241, 214, 122, 187, 227,  64,  79
    },
    .sbox4 = {
        112,  44, 179, 192, 228,  87, 234, 174,  35, 107,  69, 165, 237,  79,  29, 146,
        134, 175, 124,  31,  62, 220,  94,  11, 166,  57, 213,  93, 217,  90,  81, 108,
        139, 154, 251, 176, 116,  43, 240, 132, 223, 203,  52, 118, 109, 169, 209,   4,
         20,  58, 222,  17,  50, 156,  83, 242, 254, 207, 195, 122,  36, 232,  96, 105,
        170, 160, 161,  98,  84,  30, 224, 100,  16,   0, 163, 117, 138, 230,   9, 221,
        135, 131, 205, 144, 115, 246, 157, 191,  82, 216, 200, 198, 129, 111,  19,  99,
        233, 167, 159, 188,  41, 249,  47, 180, 120,   6, 231, 113, 212, 171, 136, 141,
        114, 185, 248, 172,  54,  42,  60, 241,  64, 211, 187,  67,  21, 173, 119, 128,
        130, 236,  39, 229, 133,  53,  12,  65, 239, 147,  25,  33,  14,  78, 101, 189,
        184, 143, 235, 206,  48,  95, 197,  26, 225, 202,  71,  61,   1, 214,  86,  77,
         13, 102, 204,  45,  18,  32, 177, 153,  76, 194, 126,   5, 183,  49,  23, 215,
         88,  97,  27,  28,  15,  22,  24,  34,  68, 178, 181, 145,   8, 168, 252,  80,
        208, 125, 137, 151,  91, 149, 255, 210, 196,  72, 247, 219,   3, 218,  63, 148,
         92,   2,  74,  51, 103, 243, 127, 226, 155,  38,  55,  59, 150,  75, 190,  46,
        121, 140, 110, 142, 245, 182, 253,  89, 152, 106,  70, 186,  37,  66, 162, 250,
          7,  85, 238,  10,  73, 104,  56, 164,  40, 123, 201, 193, 227, 244, 199, 158
    }
};
#define CAMELLIA_SIGMA1_VALUE (camellia.sigma1)
#define CAMELLIA_SIGMA2_VALUE (camellia.sigma2)
#define CAMELLIA_SIGMA3_VALUE (camellia.sigma3)
#define CAMELLIA_SIGMA4_VALUE (camellia.sigma4)
#define CAMELLIA_SBOX1_TABLE (camellia.sbox1)
#define CAMELLIA_SBOX2_TABLE (camellia.sbox2)
#define CAMELLIA_SBOX3_TABLE (camellia.sbox3)
#define CAMELLIA_SBOX4_TABLE (camellia.sbox4)
#endif

/* RFC 3713 F-function */
static uint64_t f(uint64_t fIn, uint64_t ke) {
    uint64_t fOut;
    uint64_t x;
    uint8_t t1, t2, t3, t4, t5, t6, t7, t8;
    uint8_t y1, y2, y3, y4, y5, y6, y7, y8;

    x = fIn ^ ke;
    t1 = x >> 56, t1 = CAMELLIA_SBOX1_TABLE[t1];
    t2 = x >> 48, t2 = CAMELLIA_SBOX2_TABLE[t2];
    t3 = x >> 40, t3 = CAMELLIA_SBOX3_TABLE[t3];
    t4 = x >> 32, t4 = CAMELLIA_SBOX4_TABLE[t4];
    t5 = x >> 24, t5 = CAMELLIA_SBOX2_TABLE[t5];
    t6 = x >> 16, t6 = CAMELLIA_SBOX3_TABLE[t6];
    t7 = x >>  8, t7 = CAMELLIA_SBOX4_TABLE[t7];
    t8 = x >>  0, t8 = CAMELLIA_SBOX1_TABLE[t8];
    y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;
    y4 = y8 ^ t1 ^ t2 ^ t3;
    y7 = y4 ^ t2 ^ t7 ^ t8;
    y3 = y7 ^ t1 ^ t2 ^ t4;
    y6 = y3 ^ t1 ^ t6 ^ t7;
    y2 = y6 ^ t1 ^ t3 ^ t4;
    y5 = y2 ^ t4 ^ t5 ^ t6;
    y1 = y5 ^ t2 ^ t3 ^ t4;
    fOut = (uint64_t)y1 << 56 | (uint64_t)y2 << 48 |
           (uint64_t)y3 << 40 | (uint64_t)y4 << 32 |
           (uint64_t)y5 << 24 | (uint64_t)y6 << 16 |
           (uint64_t)y7 <<  8 | (uint64_t)y8 <<  0;
    return fOut;
}

/* RFC 3713 FL-function */
static uint64_t fl(uint64_t flIn, uint64_t ke) {
    uint64_t flOut;
    uint32_t x1, x2;
    uint32_t k1, k2;

    x1 = flIn >> 32, x2 = flIn;
    k1 = ke >> 32, k2 = ke;
    x2 ^= r32(x1 & k1, 1), x1 ^= x2 | k2;
    flOut = (uint64_t)x1 << 32 | x2;
    return flOut;
}

/* RFC 3713 FLINV-function */
static uint64_t flinv(uint64_t flinvIn, uint64_t ke) {
    uint64_t flinvOut;
    uint32_t y1, y2;
    uint32_t k1, k2;

    y1 = flinvIn >> 32, y2 = flinvIn;
    k1 = ke >> 32, k2 = ke;
    y1 ^= y2 | k2, y2 ^= r32(y1 & k1, 1);
    flinvOut = (uint64_t)y1 << 32 | y2;
    return flinvOut;
}

/* Key scheduling function - simplified for 128-bit only */
static __attribute__((noinline)) void camellia_keysche_128_encrypt_impl(const uint8_t *k,
                                                                        CamelliaData *data) {
    uint64_t kl[2], kr[2];
    uint64_t d1, d2;
    uint64_t ka[2];

    data->type = Camellia128Encrypt;

    kl[0] = n8u64(k + 0);
    kl[1] = n8u64(k + 8);
    kr[0] = 0;
    kr[1] = 0;

    d1 = kl[0] ^ kr[0];
    d2 = kl[1] ^ kr[1];
    d2 ^= f(d1, CAMELLIA_SIGMA1_VALUE);
    d1 ^= f(d2, CAMELLIA_SIGMA2_VALUE);
    d1 ^= kl[0];
    d2 ^= kl[1];
    d2 ^= f(d1, CAMELLIA_SIGMA3_VALUE);
    d1 ^= f(d2, CAMELLIA_SIGMA4_VALUE);
    ka[0] = d1;
    ka[1] = d2;

    r128(kl,   0, &data->kw1, &data->kw2);
    r128(ka,   0, &data->k1,  &data->k2);
    r128(kl,  15, &data->k3,  &data->k4);
    r128(ka,  15, &data->k5,  &data->k6);
    r128(ka,  30, &data->ke1, &data->ke2);
    r128(kl,  45, &data->k7,  &data->k8);
    r128(ka,  45, &data->k9,  NULL);
    r128(kl,  60, NULL,       &data->k10);
    r128(ka,  60, &data->k11, &data->k12);
    r128(kl,  77, &data->ke3, &data->ke4);
    r128(kl,  94, &data->k13, &data->k14);
    r128(ka,  94, &data->k15, &data->k16);
    r128(kl, 111, &data->k17, &data->k18);
    r128(ka, 111, &data->kw3, &data->kw4);
}

int camelliaKeysche(CamelliaKeytype type, const uint8_t *k,
                    CamelliaData *data) {
    if (type != Camellia128Encrypt || k == NULL || data == NULL) {
        return -1;
    }

    camellia_keysche_128_encrypt_impl(k, data);
    return 0;
}

/* Key swap function to convert encrypt/decrypt keys */
int camelliaKeyswap(CamelliaData *data) {
    int status = -1;

    /* Support both encrypt and decrypt key types */
    if (data->type != Camellia128Encrypt && data->type != Camellia128Decrypt) {
        goto error;
    }

    /* Swap keys for 128-bit */
    s64(data->kw1, data->kw3);
    s64(data->kw2, data->kw4);
    s64(data->k1,  data->k18);
    s64(data->k2,  data->k17);
    s64(data->k3,  data->k16);
    s64(data->k4,  data->k15);
    s64(data->k5,  data->k14);
    s64(data->k6,  data->k13);
    s64(data->k7,  data->k12);
    s64(data->k8,  data->k11);
    s64(data->k9,  data->k10);
    s64(data->ke1, data->ke4);
    s64(data->ke2, data->ke3);

    /* Update key type */
    if (data->type == Camellia128Encrypt) {
        data->type = Camellia128Decrypt;
    } else {
        data->type = Camellia128Encrypt;
    }

    status = 0;
error:
    return status;
}

/* Data randomization function (encryption/decryption) */
int camelliaDatarand(const uint8_t *m, const CamelliaData *data,
                     uint8_t *c) {
    int status = -1;
    uint64_t d1, d2;

    /* Support both encrypt and decrypt */
    if (data->type != Camellia128Encrypt && data->type != Camellia128Decrypt) {
        goto error;
    }

    /* Load input data */
    d1 = n8u64(m +  0);
    d2 = n8u64(m +  8);

    /* Initial whitening */
    d1 ^= data->kw1;
    d2 ^= data->kw2;

    /* Main rounds */
    d2 ^= f(d1, data->k1);
    d1 ^= f(d2, data->k2);
    d2 ^= f(d1, data->k3);
    d1 ^= f(d2, data->k4);
    d2 ^= f(d1, data->k5);
    d1 ^= f(d2, data->k6);
    d1 = fl(d1, data->ke1);
    d2 = flinv(d2, data->ke2);
    d2 ^= f(d1, data->k7);
    d1 ^= f(d2, data->k8);
    d2 ^= f(d1, data->k9);
    d1 ^= f(d2, data->k10);
    d2 ^= f(d1, data->k11);
    d1 ^= f(d2, data->k12);
    d1 = fl(d1, data->ke3);
    d2 = flinv(d2, data->ke4);
    d2 ^= f(d1, data->k13);
    d1 ^= f(d2, data->k14);
    d2 ^= f(d1, data->k15);
    d1 ^= f(d2, data->k16);
    d2 ^= f(d1, data->k17);
    d1 ^= f(d2, data->k18);

    /* Final whitening */
    d2 ^= data->kw3;
    d1 ^= data->kw4;

    /* Store output data */
    u8n64_set(d2, c + 0);
    u8n64_set(d1, c + 8);

    status = 0;
error:
    return status;
}
