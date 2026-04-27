#ifndef CONSTXOR_TABLES_H
#define CONSTXOR_TABLES_H

#include <stdint.h>

const uint64_t *constxor_threefish_c240(void);
const uint8_t *constxor_threefish_r512(void);
const uint8_t *constxor_threefish_p512(void);

#endif /* CONSTXOR_TABLES_H */
