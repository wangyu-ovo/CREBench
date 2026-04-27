#include <string.h>
#include "lea.h"
#include "lea-utility.h"

#ifdef CONSTXOR_LEA_TABLES
#include "constxor_tables.h"
#define LEA_DELTA_TABLE ((const word32 (*)[36])constxor_lea_delta())
#else
#define LEA_DELTA_TABLE (delta)
#endif

void lea_key_schedule(word32 rkey[LEA_TRANSFORMED_KEY_WORDS], const word32 key[LEA_KEY_BYTES / 4])
{
    // printf("Original Key:\n");
    // for (int i = 0; i < LEA_KEY_BYTES / 4; i++) {
    //     printf("%08x ", key[i]);
    // }
    // printf("\n");
    rkey[  0] = rotlConstant( key[  0] + LEA_DELTA_TABLE[0][ 0],1);
    rkey[  6] = rotlConstant(rkey[  0] + LEA_DELTA_TABLE[1][ 1],1);
    rkey[ 12] = rotlConstant(rkey[  6] + LEA_DELTA_TABLE[2][ 2],1);
    rkey[ 18] = rotlConstant(rkey[ 12] + LEA_DELTA_TABLE[3][ 3],1);
    rkey[ 24] = rotlConstant(rkey[ 18] + LEA_DELTA_TABLE[0][ 4],1);
    rkey[ 30] = rotlConstant(rkey[ 24] + LEA_DELTA_TABLE[1][ 5],1);
    rkey[ 36] = rotlConstant(rkey[ 30] + LEA_DELTA_TABLE[2][ 6],1);
    rkey[ 42] = rotlConstant(rkey[ 36] + LEA_DELTA_TABLE[3][ 7],1);
    rkey[ 48] = rotlConstant(rkey[ 42] + LEA_DELTA_TABLE[0][ 8],1);
    rkey[ 54] = rotlConstant(rkey[ 48] + LEA_DELTA_TABLE[1][ 9],1);
    rkey[ 60] = rotlConstant(rkey[ 54] + LEA_DELTA_TABLE[2][10],1);
    rkey[ 66] = rotlConstant(rkey[ 60] + LEA_DELTA_TABLE[3][11],1);
    rkey[ 72] = rotlConstant(rkey[ 66] + LEA_DELTA_TABLE[0][12],1);
    rkey[ 78] = rotlConstant(rkey[ 72] + LEA_DELTA_TABLE[1][13],1);
    rkey[ 84] = rotlConstant(rkey[ 78] + LEA_DELTA_TABLE[2][14],1);
    rkey[ 90] = rotlConstant(rkey[ 84] + LEA_DELTA_TABLE[3][15],1);
    rkey[ 96] = rotlConstant(rkey[ 90] + LEA_DELTA_TABLE[0][16],1);
    rkey[102] = rotlConstant(rkey[ 96] + LEA_DELTA_TABLE[1][17],1);
    rkey[108] = rotlConstant(rkey[102] + LEA_DELTA_TABLE[2][18],1);
    rkey[114] = rotlConstant(rkey[108] + LEA_DELTA_TABLE[3][19],1);
    rkey[120] = rotlConstant(rkey[114] + LEA_DELTA_TABLE[0][20],1);
    rkey[126] = rotlConstant(rkey[120] + LEA_DELTA_TABLE[1][21],1);
    rkey[132] = rotlConstant(rkey[126] + LEA_DELTA_TABLE[2][22],1);
    rkey[138] = rotlConstant(rkey[132] + LEA_DELTA_TABLE[3][23],1);

    rkey[  1] = rkey[  3] = rkey[  5] = rotlConstant( key[  1] + LEA_DELTA_TABLE[0][ 1],3);
    rkey[  7] = rkey[  9] = rkey[ 11] = rotlConstant(rkey[  1] + LEA_DELTA_TABLE[1][ 2],3);
    rkey[ 13] = rkey[ 15] = rkey[ 17] = rotlConstant(rkey[  7] + LEA_DELTA_TABLE[2][ 3],3);
    rkey[ 19] = rkey[ 21] = rkey[ 23] = rotlConstant(rkey[ 13] + LEA_DELTA_TABLE[3][ 4],3);
    rkey[ 25] = rkey[ 27] = rkey[ 29] = rotlConstant(rkey[ 19] + LEA_DELTA_TABLE[0][ 5],3);
    rkey[ 31] = rkey[ 33] = rkey[ 35] = rotlConstant(rkey[ 25] + LEA_DELTA_TABLE[1][ 6],3);
    rkey[ 37] = rkey[ 39] = rkey[ 41] = rotlConstant(rkey[ 31] + LEA_DELTA_TABLE[2][ 7],3);
    rkey[ 43] = rkey[ 45] = rkey[ 47] = rotlConstant(rkey[ 37] + LEA_DELTA_TABLE[3][ 8],3);
    rkey[ 49] = rkey[ 51] = rkey[ 53] = rotlConstant(rkey[ 43] + LEA_DELTA_TABLE[0][ 9],3);
    rkey[ 55] = rkey[ 57] = rkey[ 59] = rotlConstant(rkey[ 49] + LEA_DELTA_TABLE[1][10],3);
    rkey[ 61] = rkey[ 63] = rkey[ 65] = rotlConstant(rkey[ 55] + LEA_DELTA_TABLE[2][11],3);
    rkey[ 67] = rkey[ 69] = rkey[ 71] = rotlConstant(rkey[ 61] + LEA_DELTA_TABLE[3][12],3);
    rkey[ 73] = rkey[ 75] = rkey[ 77] = rotlConstant(rkey[ 67] + LEA_DELTA_TABLE[0][13],3);
    rkey[ 79] = rkey[ 81] = rkey[ 83] = rotlConstant(rkey[ 73] + LEA_DELTA_TABLE[1][14],3);
    rkey[ 85] = rkey[ 87] = rkey[ 89] = rotlConstant(rkey[ 79] + LEA_DELTA_TABLE[2][15],3);
    rkey[ 91] = rkey[ 93] = rkey[ 95] = rotlConstant(rkey[ 85] + LEA_DELTA_TABLE[3][16],3);
    rkey[ 97] = rkey[ 99] = rkey[101] = rotlConstant(rkey[ 91] + LEA_DELTA_TABLE[0][17],3);
    rkey[103] = rkey[105] = rkey[107] = rotlConstant(rkey[ 97] + LEA_DELTA_TABLE[1][18],3);
    rkey[109] = rkey[111] = rkey[113] = rotlConstant(rkey[103] + LEA_DELTA_TABLE[2][19],3);
    rkey[115] = rkey[117] = rkey[119] = rotlConstant(rkey[109] + LEA_DELTA_TABLE[3][20],3);
    rkey[121] = rkey[123] = rkey[125] = rotlConstant(rkey[115] + LEA_DELTA_TABLE[0][21],3);
    rkey[127] = rkey[129] = rkey[131] = rotlConstant(rkey[121] + LEA_DELTA_TABLE[1][22],3);
    rkey[133] = rkey[135] = rkey[137] = rotlConstant(rkey[127] + LEA_DELTA_TABLE[2][23],3);
    rkey[139] = rkey[141] = rkey[143] = rotlConstant(rkey[133] + LEA_DELTA_TABLE[3][24],3);

    rkey[  2] = rotlConstant( key[  2] + LEA_DELTA_TABLE[0][ 2],6);
    rkey[  8] = rotlConstant(rkey[  2] + LEA_DELTA_TABLE[1][ 3],6);
    rkey[ 14] = rotlConstant(rkey[  8] + LEA_DELTA_TABLE[2][ 4],6);
    rkey[ 20] = rotlConstant(rkey[ 14] + LEA_DELTA_TABLE[3][ 5],6);
    rkey[ 26] = rotlConstant(rkey[ 20] + LEA_DELTA_TABLE[0][ 6],6);
    rkey[ 32] = rotlConstant(rkey[ 26] + LEA_DELTA_TABLE[1][ 7],6);
    rkey[ 38] = rotlConstant(rkey[ 32] + LEA_DELTA_TABLE[2][ 8],6);
    rkey[ 44] = rotlConstant(rkey[ 38] + LEA_DELTA_TABLE[3][ 9],6);
    rkey[ 50] = rotlConstant(rkey[ 44] + LEA_DELTA_TABLE[0][10],6);
    rkey[ 56] = rotlConstant(rkey[ 50] + LEA_DELTA_TABLE[1][11],6);
    rkey[ 62] = rotlConstant(rkey[ 56] + LEA_DELTA_TABLE[2][12],6);
    rkey[ 68] = rotlConstant(rkey[ 62] + LEA_DELTA_TABLE[3][13],6);
    rkey[ 74] = rotlConstant(rkey[ 68] + LEA_DELTA_TABLE[0][14],6);
    rkey[ 80] = rotlConstant(rkey[ 74] + LEA_DELTA_TABLE[1][15],6);
    rkey[ 86] = rotlConstant(rkey[ 80] + LEA_DELTA_TABLE[2][16],6);
    rkey[ 92] = rotlConstant(rkey[ 86] + LEA_DELTA_TABLE[3][17],6);
    rkey[ 98] = rotlConstant(rkey[ 92] + LEA_DELTA_TABLE[0][18],6);
    rkey[104] = rotlConstant(rkey[ 98] + LEA_DELTA_TABLE[1][19],6);
    rkey[110] = rotlConstant(rkey[104] + LEA_DELTA_TABLE[2][20],6);
    rkey[116] = rotlConstant(rkey[110] + LEA_DELTA_TABLE[3][21],6);
    rkey[122] = rotlConstant(rkey[116] + LEA_DELTA_TABLE[0][22],6);
    rkey[128] = rotlConstant(rkey[122] + LEA_DELTA_TABLE[1][23],6);
    rkey[134] = rotlConstant(rkey[128] + LEA_DELTA_TABLE[2][24],6);
    rkey[140] = rotlConstant(rkey[134] + LEA_DELTA_TABLE[3][25],6);

    rkey[  4] = rotlConstant( key[  3] + LEA_DELTA_TABLE[0][ 3],11);
    rkey[ 10] = rotlConstant(rkey[  4] + LEA_DELTA_TABLE[1][ 4],11);
    rkey[ 16] = rotlConstant(rkey[ 10] + LEA_DELTA_TABLE[2][ 5],11);
    rkey[ 22] = rotlConstant(rkey[ 16] + LEA_DELTA_TABLE[3][ 6],11);
    rkey[ 28] = rotlConstant(rkey[ 22] + LEA_DELTA_TABLE[0][ 7],11);
    rkey[ 34] = rotlConstant(rkey[ 28] + LEA_DELTA_TABLE[1][ 8],11);
    rkey[ 40] = rotlConstant(rkey[ 34] + LEA_DELTA_TABLE[2][ 9],11);
    rkey[ 46] = rotlConstant(rkey[ 40] + LEA_DELTA_TABLE[3][10],11);
    rkey[ 52] = rotlConstant(rkey[ 46] + LEA_DELTA_TABLE[0][11],11);
    rkey[ 58] = rotlConstant(rkey[ 52] + LEA_DELTA_TABLE[1][12],11);
    rkey[ 64] = rotlConstant(rkey[ 58] + LEA_DELTA_TABLE[2][13],11);
    rkey[ 70] = rotlConstant(rkey[ 64] + LEA_DELTA_TABLE[3][14],11);
    rkey[ 76] = rotlConstant(rkey[ 70] + LEA_DELTA_TABLE[0][15],11);
    rkey[ 82] = rotlConstant(rkey[ 76] + LEA_DELTA_TABLE[1][16],11);
    rkey[ 88] = rotlConstant(rkey[ 82] + LEA_DELTA_TABLE[2][17],11);
    rkey[ 94] = rotlConstant(rkey[ 88] + LEA_DELTA_TABLE[3][18],11);
    rkey[100] = rotlConstant(rkey[ 94] + LEA_DELTA_TABLE[0][19],11);
    rkey[106] = rotlConstant(rkey[100] + LEA_DELTA_TABLE[1][20],11);
    rkey[112] = rotlConstant(rkey[106] + LEA_DELTA_TABLE[2][21],11);
    rkey[118] = rotlConstant(rkey[112] + LEA_DELTA_TABLE[3][22],11);
    rkey[124] = rotlConstant(rkey[118] + LEA_DELTA_TABLE[0][23],11);
    rkey[130] = rotlConstant(rkey[124] + LEA_DELTA_TABLE[1][24],11);
    rkey[136] = rotlConstant(rkey[130] + LEA_DELTA_TABLE[2][25],11);
    rkey[142] = rotlConstant(rkey[136] + LEA_DELTA_TABLE[3][26],11);

    // for (int i = 0; i < LEA_TRANSFORMED_KEY_WORDS; i++) {
    //     printf("rkey[%d] = %08x ", i, rkey[i]);
    // }
}
