#ifndef CONSTXOR_TABLES_H
#define CONSTXOR_TABLES_H

#include <stdint.h>

const uint8_t *constxor_sm4_sbox(void);
const uint32_t *constxor_sm4_fk(void);
const uint32_t *constxor_sm4_ck(void);

#endif /* CONSTXOR_TABLES_H */
