#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "des.h"

// DES permutation tables and S-boxes
static const int initial_key_permutation[] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
};

static const int initial_message_permutation[] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

static const int key_shift_sizes[] = {
    -1, 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

static const int sub_key_permutation[] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

static const int message_expansion[] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
};

static const int S1[] = {
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
};

static const int S2[] = {
    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
};

static const int S3[] = {
    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
};

static const int S4[] = {
    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
    3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
};

static const int S5[] = {
    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
};

static const int S6[] = {
    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
};

static const int S7[] = {
    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
};

static const int S8[] = {
    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
};

static const int right_sub_message_permutation[] = {
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
};

static const int final_message_permutation[] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};

void des_generate_key(uint8_t* key) {
    if (!key) return;

    srand((unsigned int)time(NULL));
    for (int i = 0; i < DES_KEY_SIZE; i++) {
        key[i] = (uint8_t)(rand() % 256);
    }
}

void des_generate_subkeys(const uint8_t* main_key, des_key_set* key_sets) {
    if (!main_key || !key_sets) return;

    int i, j;
    int shift_size;
    uint8_t shift_byte, first_shift_bits, second_shift_bits, third_shift_bits, fourth_shift_bits;

    // Initialize key_sets[0]
    memset(key_sets[0].k, 0, 8);

    // Apply PC-1 permutation to get 56-bit key
    for (i = 0; i < 56; i++) {
        shift_size = initial_key_permutation[i];
        shift_byte = 0x80 >> ((shift_size - 1) % 8);
        shift_byte &= main_key[(shift_size - 1) / 8];
        shift_byte <<= ((shift_size - 1) % 8);
        key_sets[0].k[i / 8] |= (shift_byte >> i % 8);
    }

    // Split into C and D (28 bits each)
    memcpy(key_sets[0].c, key_sets[0].k, 4);
    key_sets[0].c[3] &= 0xF0;

    for (i = 0; i < 3; i++) {
        key_sets[0].d[i] = (key_sets[0].k[i + 3] & 0x0F) << 4;
        key_sets[0].d[i] |= (key_sets[0].k[i + 4] & 0xF0) >> 4;
    }
    key_sets[0].d[3] = (key_sets[0].k[6] & 0x0F) << 4;

    // Generate 16 subkeys
    for (i = 1; i < 17; i++) {
        memcpy(&key_sets[i], &key_sets[i - 1], sizeof(des_key_set));

        shift_size = key_shift_sizes[i];
        if (shift_size == 1) {
            shift_byte = 0x80;
        } else {
            shift_byte = 0xC0;
        }

        // Shift C
        first_shift_bits = shift_byte & key_sets[i].c[0];
        second_shift_bits = shift_byte & key_sets[i].c[1];
        third_shift_bits = shift_byte & key_sets[i].c[2];
        fourth_shift_bits = shift_byte & key_sets[i].c[3];

        key_sets[i].c[0] <<= shift_size;
        key_sets[i].c[0] |= (second_shift_bits >> (8 - shift_size));

        key_sets[i].c[1] <<= shift_size;
        key_sets[i].c[1] |= (third_shift_bits >> (8 - shift_size));

        key_sets[i].c[2] <<= shift_size;
        key_sets[i].c[2] |= (fourth_shift_bits >> (8 - shift_size));

        key_sets[i].c[3] <<= shift_size;
        key_sets[i].c[3] |= (first_shift_bits >> (4 - shift_size));

        // Shift D
        first_shift_bits = shift_byte & key_sets[i].d[0];
        second_shift_bits = shift_byte & key_sets[i].d[1];
        third_shift_bits = shift_byte & key_sets[i].d[2];
        fourth_shift_bits = shift_byte & key_sets[i].d[3];

        key_sets[i].d[0] <<= shift_size;
        key_sets[i].d[0] |= (second_shift_bits >> (8 - shift_size));

        key_sets[i].d[1] <<= shift_size;
        key_sets[i].d[1] |= (third_shift_bits >> (8 - shift_size));

        key_sets[i].d[2] <<= shift_size;
        key_sets[i].d[2] |= (fourth_shift_bits >> (8 - shift_size));

        key_sets[i].d[3] <<= shift_size;
        key_sets[i].d[3] |= (first_shift_bits >> (4 - shift_size));

        // Apply PC-2 permutation to generate subkey
        memset(key_sets[i].k, 0, 6);
        for (j = 0; j < 48; j++) {
            shift_size = sub_key_permutation[j];
            if (shift_size <= 28) {
                shift_byte = 0x80 >> ((shift_size - 1) % 8);
                shift_byte &= key_sets[i].c[(shift_size - 1) / 8];
                shift_byte <<= ((shift_size - 1) % 8);
            } else {
                shift_byte = 0x80 >> ((shift_size - 29) % 8);
                shift_byte &= key_sets[i].d[(shift_size - 29) / 8];
                shift_byte <<= ((shift_size - 29) % 8);
            }
            key_sets[i].k[j / 8] |= (shift_byte >> j % 8);
        }
    }
}

void des_process_block(const uint8_t* input, uint8_t* output,
                      const des_key_set* key_sets, int mode) {
    if (!input || !output || !key_sets) return;

    int i, k;
    int shift_size;
    uint8_t shift_byte;

    uint8_t initial_permutation[8];
    memset(initial_permutation, 0, 8);
    memset(output, 0, 8);

    // Apply initial permutation
    for (i = 0; i < 64; i++) {
        shift_size = initial_message_permutation[i];
        shift_byte = 0x80 >> ((shift_size - 1) % 8);
        shift_byte &= input[(shift_size - 1) / 8];
        shift_byte <<= ((shift_size - 1) % 8);
        initial_permutation[i / 8] |= (shift_byte >> i % 8);
    }

    // Split into L and R (32 bits each)
    uint8_t l[4], r[4];
    memcpy(l, initial_permutation, 4);
    memcpy(r, initial_permutation + 4, 4);

    uint8_t ln[4], rn[4], er[6], ser[4];

    // 16 rounds of DES
    for (k = 1; k <= 16; k++) {
        memcpy(ln, r, 4);

        // Expand R from 32 to 48 bits
        memset(er, 0, 6);
        for (i = 0; i < 48; i++) {
            shift_size = message_expansion[i];
            shift_byte = 0x80 >> ((shift_size - 1) % 8);
            shift_byte &= r[(shift_size - 1) / 8];
            shift_byte <<= ((shift_size - 1) % 8);
            er[i / 8] |= (shift_byte >> i % 8);
        }

        int key_index;
        if (mode == DES_DECRYPT) {
            key_index = 17 - k;
        } else {
            key_index = k;
        }

        // XOR with subkey
        for (i = 0; i < 6; i++) {
            er[i] ^= key_sets[key_index].k[i];
        }

        // Apply S-boxes
        memset(ser, 0, 4);

        uint8_t row, column;

        // S-box 1
        row = 0;
        row |= ((er[0] & 0x80) >> 6);
        row |= ((er[0] & 0x04) >> 2);
        column = 0;
        column |= ((er[0] & 0x78) >> 3);
        ser[0] |= ((uint8_t)S1[row * 16 + column] << 4);

        row = 0;
        row |= (er[0] & 0x02);
        row |= ((er[1] & 0x10) >> 4);
        column = 0;
        column |= ((er[0] & 0x01) << 3);
        column |= ((er[1] & 0xE0) >> 5);
        ser[0] |= (uint8_t)S2[row * 16 + column];

        // S-box 2
        row = 0;
        row |= ((er[1] & 0x08) >> 2);
        row |= ((er[2] & 0x40) >> 6);
        column = 0;
        column |= ((er[1] & 0x07) << 1);
        column |= ((er[2] & 0x80) >> 7);
        ser[1] |= ((uint8_t)S3[row * 16 + column] << 4);

        row = 0;
        row |= ((er[2] & 0x20) >> 4);
        row |= (er[2] & 0x01);
        column = 0;
        column |= ((er[2] & 0x1E) >> 1);
        ser[1] |= (uint8_t)S4[row * 16 + column];

        // S-box 3
        row = 0;
        row |= ((er[3] & 0x80) >> 6);
        row |= ((er[3] & 0x04) >> 2);
        column = 0;
        column |= ((er[3] & 0x78) >> 3);
        ser[2] |= ((uint8_t)S5[row * 16 + column] << 4);

        row = 0;
        row |= (er[3] & 0x02);
        row |= ((er[4] & 0x10) >> 4);
        column = 0;
        column |= ((er[3] & 0x01) << 3);
        column |= ((er[4] & 0xE0) >> 5);
        ser[2] |= (uint8_t)S6[row * 16 + column];

        // S-box 4
        row = 0;
        row |= ((er[4] & 0x08) >> 2);
        row |= ((er[5] & 0x40) >> 6);
        column = 0;
        column |= ((er[4] & 0x07) << 1);
        column |= ((er[5] & 0x80) >> 7);
        ser[3] |= ((uint8_t)S7[row * 16 + column] << 4);

        row = 0;
        row |= ((er[5] & 0x20) >> 4);
        row |= (er[5] & 0x01);
        column = 0;
        column |= ((er[5] & 0x1E) >> 1);
        ser[3] |= (uint8_t)S8[row * 16 + column];

        // Apply P permutation
        memset(rn, 0, 4);
        for (i = 0; i < 32; i++) {
            shift_size = right_sub_message_permutation[i];
            shift_byte = 0x80 >> ((shift_size - 1) % 8);
            shift_byte &= ser[(shift_size - 1) / 8];
            shift_byte <<= ((shift_size - 1) % 8);
            rn[i / 8] |= (shift_byte >> i % 8);
        }

        // XOR with L
        for (i = 0; i < 4; i++) {
            rn[i] ^= l[i];
        }

        // Update L and R
        memcpy(l, ln, 4);
        memcpy(r, rn, 4);
    }

    // Final permutation
    uint8_t pre_end_permutation[8];
    memcpy(pre_end_permutation, r, 4);
    memcpy(pre_end_permutation + 4, l, 4);

    for (i = 0; i < 64; i++) {
        shift_size = final_message_permutation[i];
        shift_byte = 0x80 >> ((shift_size - 1) % 8);
        shift_byte &= pre_end_permutation[(shift_size - 1) / 8];
        shift_byte <<= ((shift_size - 1) % 8);
        output[i / 8] |= (shift_byte >> i % 8);
    }
}

void des_print_hex(const uint8_t* data, size_t length) {
    if (!data) return;

    for (size_t i = 0; i < length; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

void des_print_binary(const uint8_t* data, size_t length) {
    if (!data) return;

    for (size_t i = 0; i < length; i++) {
        for (int j = 7; j >= 0; j--) {
            printf("%d", (data[i] >> j) & 1);
        }
        printf(" ");
    }
    printf("\n");
}
