#ifndef CONSTXOR_TABLES_H
#define CONSTXOR_TABLES_H

#include <stdint.h>

const uint8_t *constxor_aes_sbox(void);
const uint32_t *constxor_aes_rcon(void);

#endif /* CONSTXOR_TABLES_H */
