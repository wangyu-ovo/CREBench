// Implement fast multiplication and its inverse under 2^16+1 modulo
// 0 represents 2^16 = -1 (mod 2^16+1)
#include "idea.h"

#ifdef CONSTXOR_IDEA_TABLES
#include "constxor_tables.h"
#define IDEA_MAGIC_TABLE (constxor_idea_magic())
#else
static const uint32_t idea_magic[1] = {0x10001U};
#define IDEA_MAGIC_TABLE (idea_magic)
#endif

#define IDEA_MODULUS_VALUE (IDEA_MAGIC_TABLE[0])

uint16_t low16(uint32_t x) {
    return (uint16_t)(x & 0xFFFF);
}

uint16_t high16(uint32_t x) {
    return (uint16_t)(x >> 16);
}

uint16_t MUL(uint16_t a, uint16_t b) {
    if (a == 0) return (uint16_t)(1 - b);
    if (b == 0) return (uint16_t)(1 - a);
    uint32_t p = (uint32_t)a * b;
    uint32_t low = low16(p);
    uint32_t high = high16(p);
    return (uint16_t)(low - high + (low < high ? 1U : 0U));
}

uint16_t MulInv(uint16_t x) {
    uint16_t y = x;
    for (unsigned int i = 0; i < 15; i++) {
        y = MUL(y, y);
        y = MUL(y, x);
    }
    return y;
}

uint16_t AddInv(uint16_t x) {
    return (uint16_t)(0 - x);
}
