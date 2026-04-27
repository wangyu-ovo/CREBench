// implement multiplication in GF(2^8) and the square transformation

#include <stdbool.h>
#include "square.h"

static inline uint8_t GetByte(uint32_t word, int index)
{
    return (uint8_t)((word >> (index * 8)) & 0xFF);
}

static uint8_t GFMultiply(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if ((b & 1) != 0) {
            p ^= a;
        }
        bool hi_bit_set = (a & 0x80) != 0;
        a <<= 1;
        if (hi_bit_set) {
            a ^= 0xf5;
        }
        b >>= 1;
    }
    return p;
}

void square_transform(uint32_t in[4], uint32_t out[4])
{
    static const uint8_t G[4][4] =
    {
        {0x02U, 0x01U, 0x01U, 0x03U},
        {0x03U, 0x02U, 0x01U, 0x01U},
        {0x01U, 0x03U, 0x02U, 0x01U},
        {0x01U, 0x01U, 0x03U, 0x02U}
    };

    for (int i = 0; i < 4; i++)
    {
        uint32_t temp = 0;
        
        for (int j = 0; j < 4; j++) 
        {
            uint8_t res_byte = 0;
            
            for (int k = 0; k < 4; k++)
            {
                uint8_t input_byte = GetByte(in[i], 3 - k);
                
                res_byte ^= GFMultiply(input_byte, G[k][j]);
            }
            
            temp |= ((uint32_t)res_byte) << ((3 - j) * 8);
        }
        
        out[i] = temp;
    }
}