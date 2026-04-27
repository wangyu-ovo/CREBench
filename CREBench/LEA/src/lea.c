#include "lea.h"
#include "lea-utility.h"

void lea_enc(const uint8_t in[LEA_BLOCK_BYTES], uint8_t out[LEA_BLOCK_BYTES], const uint8_t key[LEA_KEY_BYTES]) {
    uint32_t m_rkey[LEA_TRANSFORMED_KEY_WORDS] = {0}, m_temp[4] = {0};
    uint32_t key_32[LEA_KEY_BYTES / 4] = {0};
    for (int i = 0; i < LEA_KEY_BYTES / 4; i++) {
        key_32[i] = ((uint32_t)key[i * 4]) | ((uint32_t)key[i * 4 + 1] << 8) | ((uint32_t)key[i * 4 + 2] << 16) | ((uint32_t)key[i * 4 + 3] << 24);
    }
    lea_key_schedule(m_rkey, key_32);
    for (int i = 0; i < LEA_BLOCK_BYTES; i++) {
        m_temp[i / 4] |= (uint32_t)in[i] << (8 * (i%4)); // little-endian
    }
    // for (int i = 0; i < 4; i++) {
    //     printf("m_temp[%d]: %08x\n", i, m_temp[i]);
    // }
    m_temp[3] = rotrConstant(((m_temp[3] ^ m_rkey[  5]) + (m_temp[2] ^ m_rkey[  4])), 3);
    m_temp[2] = rotrConstant(((m_temp[2] ^ m_rkey[  3]) + (m_temp[1] ^ m_rkey[  2])), 5);
    m_temp[1] = rotlConstant(((m_temp[1] ^ m_rkey[  1]) + (m_temp[0] ^ m_rkey[  0])), 9);
    m_temp[0] = rotrConstant(((m_temp[0] ^ m_rkey[ 11]) + (m_temp[3] ^ m_rkey[ 10])), 3);
    m_temp[3] = rotrConstant(((m_temp[3] ^ m_rkey[  9]) + (m_temp[2] ^ m_rkey[  8])), 5);
    m_temp[2] = rotlConstant(((m_temp[2] ^ m_rkey[  7]) + (m_temp[1] ^ m_rkey[  6])), 9);
    m_temp[1] = rotrConstant(((m_temp[1] ^ m_rkey[ 17]) + (m_temp[0] ^ m_rkey[ 16])), 3);
    m_temp[0] = rotrConstant(((m_temp[0] ^ m_rkey[ 15]) + (m_temp[3] ^ m_rkey[ 14])), 5);
    m_temp[3] = rotlConstant(((m_temp[3] ^ m_rkey[ 13]) + (m_temp[2] ^ m_rkey[ 12])), 9);
    m_temp[2] = rotrConstant(((m_temp[2] ^ m_rkey[ 23]) + (m_temp[1] ^ m_rkey[ 22])), 3);
    m_temp[1] = rotrConstant(((m_temp[1] ^ m_rkey[ 21]) + (m_temp[0] ^ m_rkey[ 20])), 5);
    m_temp[0] = rotlConstant(((m_temp[0] ^ m_rkey[ 19]) + (m_temp[3] ^ m_rkey[ 18])), 9);

    m_temp[3] = rotrConstant(((m_temp[3] ^ m_rkey[ 29]) + (m_temp[2] ^ m_rkey[ 28])), 3);
    m_temp[2] = rotrConstant(((m_temp[2] ^ m_rkey[ 27]) + (m_temp[1] ^ m_rkey[ 26])), 5);
    m_temp[1] = rotlConstant(((m_temp[1] ^ m_rkey[ 25]) + (m_temp[0] ^ m_rkey[ 24])), 9);
    m_temp[0] = rotrConstant(((m_temp[0] ^ m_rkey[ 35]) + (m_temp[3] ^ m_rkey[ 34])), 3);
    m_temp[3] = rotrConstant(((m_temp[3] ^ m_rkey[ 33]) + (m_temp[2] ^ m_rkey[ 32])), 5);
    m_temp[2] = rotlConstant(((m_temp[2] ^ m_rkey[ 31]) + (m_temp[1] ^ m_rkey[ 30])), 9);
    m_temp[1] = rotrConstant(((m_temp[1] ^ m_rkey[ 41]) + (m_temp[0] ^ m_rkey[ 40])), 3);
    m_temp[0] = rotrConstant(((m_temp[0] ^ m_rkey[ 39]) + (m_temp[3] ^ m_rkey[ 38])), 5);
    m_temp[3] = rotlConstant(((m_temp[3] ^ m_rkey[ 37]) + (m_temp[2] ^ m_rkey[ 36])), 9);
    m_temp[2] = rotrConstant(((m_temp[2] ^ m_rkey[ 47]) + (m_temp[1] ^ m_rkey[ 46])), 3);
    m_temp[1] = rotrConstant(((m_temp[1] ^ m_rkey[ 45]) + (m_temp[0] ^ m_rkey[ 44])), 5);
    m_temp[0] = rotlConstant(((m_temp[0] ^ m_rkey[ 43]) + (m_temp[3] ^ m_rkey[ 42])), 9);

    m_temp[3] = rotrConstant(((m_temp[3] ^ m_rkey[ 53]) + (m_temp[2] ^ m_rkey[ 52])), 3);
    m_temp[2] = rotrConstant(((m_temp[2] ^ m_rkey[ 51]) + (m_temp[1] ^ m_rkey[ 50])), 5);
    m_temp[1] = rotlConstant(((m_temp[1] ^ m_rkey[ 49]) + (m_temp[0] ^ m_rkey[ 48])), 9);
    m_temp[0] = rotrConstant(((m_temp[0] ^ m_rkey[ 59]) + (m_temp[3] ^ m_rkey[ 58])), 3);
    m_temp[3] = rotrConstant(((m_temp[3] ^ m_rkey[ 57]) + (m_temp[2] ^ m_rkey[ 56])), 5);
    m_temp[2] = rotlConstant(((m_temp[2] ^ m_rkey[ 55]) + (m_temp[1] ^ m_rkey[ 54])), 9);
    m_temp[1] = rotrConstant(((m_temp[1] ^ m_rkey[ 65]) + (m_temp[0] ^ m_rkey[ 64])), 3);
    m_temp[0] = rotrConstant(((m_temp[0] ^ m_rkey[ 63]) + (m_temp[3] ^ m_rkey[ 62])), 5);
    m_temp[3] = rotlConstant(((m_temp[3] ^ m_rkey[ 61]) + (m_temp[2] ^ m_rkey[ 60])), 9);
    m_temp[2] = rotrConstant(((m_temp[2] ^ m_rkey[ 71]) + (m_temp[1] ^ m_rkey[ 70])), 3);
    m_temp[1] = rotrConstant(((m_temp[1] ^ m_rkey[ 69]) + (m_temp[0] ^ m_rkey[ 68])), 5);
    m_temp[0] = rotlConstant(((m_temp[0] ^ m_rkey[ 67]) + (m_temp[3] ^ m_rkey[ 66])), 9);

    m_temp[3] = rotrConstant(((m_temp[3] ^ m_rkey[ 77]) + (m_temp[2] ^ m_rkey[ 76])), 3);
    m_temp[2] = rotrConstant(((m_temp[2] ^ m_rkey[ 75]) + (m_temp[1] ^ m_rkey[ 74])), 5);
    m_temp[1] = rotlConstant(((m_temp[1] ^ m_rkey[ 73]) + (m_temp[0] ^ m_rkey[ 72])), 9);
    m_temp[0] = rotrConstant(((m_temp[0] ^ m_rkey[ 83]) + (m_temp[3] ^ m_rkey[ 82])), 3);
    m_temp[3] = rotrConstant(((m_temp[3] ^ m_rkey[ 81]) + (m_temp[2] ^ m_rkey[ 80])), 5);
    m_temp[2] = rotlConstant(((m_temp[2] ^ m_rkey[ 79]) + (m_temp[1] ^ m_rkey[ 78])), 9);
    m_temp[1] = rotrConstant(((m_temp[1] ^ m_rkey[ 89]) + (m_temp[0] ^ m_rkey[ 88])), 3);
    m_temp[0] = rotrConstant(((m_temp[0] ^ m_rkey[ 87]) + (m_temp[3] ^ m_rkey[ 86])), 5);
    m_temp[3] = rotlConstant(((m_temp[3] ^ m_rkey[ 85]) + (m_temp[2] ^ m_rkey[ 84])), 9);
    m_temp[2] = rotrConstant(((m_temp[2] ^ m_rkey[ 95]) + (m_temp[1] ^ m_rkey[ 94])), 3);
    m_temp[1] = rotrConstant(((m_temp[1] ^ m_rkey[ 93]) + (m_temp[0] ^ m_rkey[ 92])), 5);
    m_temp[0] = rotlConstant(((m_temp[0] ^ m_rkey[ 91]) + (m_temp[3] ^ m_rkey[ 90])), 9);

    m_temp[3] = rotrConstant(((m_temp[3] ^ m_rkey[101]) + (m_temp[2] ^ m_rkey[100])), 3);
    m_temp[2] = rotrConstant(((m_temp[2] ^ m_rkey[ 99]) + (m_temp[1] ^ m_rkey[ 98])), 5);
    m_temp[1] = rotlConstant(((m_temp[1] ^ m_rkey[ 97]) + (m_temp[0] ^ m_rkey[ 96])), 9);
    m_temp[0] = rotrConstant(((m_temp[0] ^ m_rkey[107]) + (m_temp[3] ^ m_rkey[106])), 3);
    m_temp[3] = rotrConstant(((m_temp[3] ^ m_rkey[105]) + (m_temp[2] ^ m_rkey[104])), 5);
    m_temp[2] = rotlConstant(((m_temp[2] ^ m_rkey[103]) + (m_temp[1] ^ m_rkey[102])), 9);
    m_temp[1] = rotrConstant(((m_temp[1] ^ m_rkey[113]) + (m_temp[0] ^ m_rkey[112])), 3);
    m_temp[0] = rotrConstant(((m_temp[0] ^ m_rkey[111]) + (m_temp[3] ^ m_rkey[110])), 5);
    m_temp[3] = rotlConstant(((m_temp[3] ^ m_rkey[109]) + (m_temp[2] ^ m_rkey[108])), 9);
    m_temp[2] = rotrConstant(((m_temp[2] ^ m_rkey[119]) + (m_temp[1] ^ m_rkey[118])), 3);
    m_temp[1] = rotrConstant(((m_temp[1] ^ m_rkey[117]) + (m_temp[0] ^ m_rkey[116])), 5);
    m_temp[0] = rotlConstant(((m_temp[0] ^ m_rkey[115]) + (m_temp[3] ^ m_rkey[114])), 9);

    m_temp[3] = rotrConstant(((m_temp[3] ^ m_rkey[125]) + (m_temp[2] ^ m_rkey[124])), 3);
    m_temp[2] = rotrConstant(((m_temp[2] ^ m_rkey[123]) + (m_temp[1] ^ m_rkey[122])), 5);
    m_temp[1] = rotlConstant(((m_temp[1] ^ m_rkey[121]) + (m_temp[0] ^ m_rkey[120])), 9);
    m_temp[0] = rotrConstant(((m_temp[0] ^ m_rkey[131]) + (m_temp[3] ^ m_rkey[130])), 3);
    m_temp[3] = rotrConstant(((m_temp[3] ^ m_rkey[129]) + (m_temp[2] ^ m_rkey[128])), 5);
    m_temp[2] = rotlConstant(((m_temp[2] ^ m_rkey[127]) + (m_temp[1] ^ m_rkey[126])), 9);
    m_temp[1] = rotrConstant(((m_temp[1] ^ m_rkey[137]) + (m_temp[0] ^ m_rkey[136])), 3);
    m_temp[0] = rotrConstant(((m_temp[0] ^ m_rkey[135]) + (m_temp[3] ^ m_rkey[134])), 5);
    m_temp[3] = rotlConstant(((m_temp[3] ^ m_rkey[133]) + (m_temp[2] ^ m_rkey[132])), 9);
    m_temp[2] = rotrConstant(((m_temp[2] ^ m_rkey[143]) + (m_temp[1] ^ m_rkey[142])), 3);
    m_temp[1] = rotrConstant(((m_temp[1] ^ m_rkey[141]) + (m_temp[0] ^ m_rkey[140])), 5);
    m_temp[0] = rotlConstant(((m_temp[0] ^ m_rkey[139]) + (m_temp[3] ^ m_rkey[138])), 9);

    for (int i = 0; i < LEA_BLOCK_BYTES; i++) {
        out[i] = (m_temp[i / 4] >> (8 * (i % 4))) & 0xFF; // little-endian
    }
}
