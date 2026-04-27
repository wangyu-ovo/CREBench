/* camellia.h - Simplified Camellia 128-bit encryption header
 * Based on RFC 3713 and implementation from Yuichi Kobayashi <kobayasy@kobayasy.com>
 *
 * Simplified for 128-bit encryption only
 */

#ifndef _INCLUDE_camellia_h
#define _INCLUDE_camellia_h

#include <stdint.h>

/* Key type enumeration for 128-bit encryption/decryption */
typedef enum {
    Camellia128Encrypt = 1,  /* Camellia 128bit encryption key */
    Camellia128Decrypt = 2   /* Camellia 128bit decryption key */
} CamelliaKeytype;

/* Transformation table structure */
typedef struct {
    CamelliaKeytype type;                                                 /* Key type */
    uint64_t kw1, kw2, kw3, kw4;                                          /* RFC 3713 subkeys */
    uint64_t k1,  k2,  k3,  k4,  k5,  k6,  k7,  k8,  k9,  k10, k11, k12,  /* RFC 3713 subkeys */
             k13, k14, k15, k16, k17, k18;
    uint64_t ke1, ke2, ke3, ke4;                                /* RFC 3713 subkeys */
} CamelliaData;

/* Key scheduling function
 * type: Key type (Camellia128Encrypt)
 * k: Key data (16 bytes for 128-bit)
 * data: Transformation table
 * Returns: 0 on success, negative on error
 */
extern int camelliaKeysche(CamelliaKeytype type, const uint8_t *k,
                           CamelliaData *data);

/* Key swap function to convert between encrypt/decrypt keys
 * data: Transformation table
 * Returns: 0 on success, negative on error
 */
extern int camelliaKeyswap(CamelliaData *data);

/* Data randomization function (encryption/decryption)
 * m: Input data (16 bytes)
 * data: Transformation table
 * c: Output data (16 bytes)
 * Returns: 0 on success, negative on error
 */
extern int camelliaDatarand(const uint8_t *m, const CamelliaData *data,
                            uint8_t *c);

#endif  /* #ifndef _INCLUDE_camellia_h */
