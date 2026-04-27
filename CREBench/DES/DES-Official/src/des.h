#ifndef DES_H
#define DES_H

#include <stdint.h>

// DES block size is 8 bytes (64 bits)
#define DES_BLOCK_SIZE 8

// DES key size is 8 bytes (56 bits effective)
#define DES_KEY_SIZE 8

// Encryption and decryption modes
#define DES_ENCRYPT 1
#define DES_DECRYPT 0

// DES key structure containing the 16 subkeys
typedef struct {
    uint8_t k[8];    // 56-bit key after PC-1 permutation
    uint8_t c[4];    // Left half (28 bits)
    uint8_t d[4];    // Right half (28 bits)
} des_key_set;

/**
 * Generate 16 subkeys from the main DES key
 * @param main_key 8-byte DES key
 * @param key_sets Array of 17 key_set structures (index 0 unused)
 */
void des_generate_subkeys(const uint8_t* main_key, des_key_set* key_sets);

/**
 * Encrypt or decrypt a single 8-byte block using DES
 * @param input 8-byte input block
 * @param output 8-byte output block
 * @param key_sets Generated subkeys
 * @param mode DES_ENCRYPT or DES_DECRYPT
 */
void des_process_block(const uint8_t* input, uint8_t* output,
                      const des_key_set* key_sets, int mode);

/**
 * Generate a random DES key
 * @param key Output buffer for 8-byte key
 */
void des_generate_key(uint8_t* key);

/**
 * Print a byte array in hexadecimal format
 * @param data Byte array
 * @param length Length of array
 */
void des_print_hex(const uint8_t* data, size_t length);

/**
 * Print a byte array in binary format
 * @param data Byte array
 * @param length Length of array
 */
void des_print_binary(const uint8_t* data, size_t length);

#endif /* DES_H */
