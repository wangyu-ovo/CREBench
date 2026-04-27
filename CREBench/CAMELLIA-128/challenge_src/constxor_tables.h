#ifndef CONSTXOR_TABLES_H
#define CONSTXOR_TABLES_H

#include <stdint.h>

const uint64_t *constxor_camellia_sigma1(void);
const uint64_t *constxor_camellia_sigma2(void);
const uint64_t *constxor_camellia_sigma3(void);
const uint64_t *constxor_camellia_sigma4(void);
const uint8_t *constxor_camellia_sbox1(void);
const uint8_t *constxor_camellia_sbox2(void);
const uint8_t *constxor_camellia_sbox3(void);
const uint8_t *constxor_camellia_sbox4(void);

#endif /* CONSTXOR_TABLES_H */
