#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "des.h"

int main(void) {
    printf("DES Single Block Encryption/Decryption Example\n");
    printf("==============================================\n\n");

    // Example key (8 bytes)
    uint8_t key[DES_KEY_SIZE] = {
        0x13, 0x34, 0x57, 0x79,
        0x9B, 0xBC, 0xDF, 0xF1
    };

    // Example plaintext (8 bytes)
    uint8_t plaintext[DES_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF
    };

    uint8_t ciphertext[DES_BLOCK_SIZE];
    uint8_t decrypted[DES_BLOCK_SIZE];
    des_key_set key_sets[17];

    printf("Key:        ");
    des_print_hex(key, DES_KEY_SIZE);

    printf("Plaintext:  ");
    des_print_hex(plaintext, DES_BLOCK_SIZE);

    // Generate subkeys
    des_generate_subkeys(key, key_sets);
    printf("Subkeys generated successfully.\n\n");

    // Encrypt
    des_process_block(plaintext, ciphertext, key_sets, DES_ENCRYPT);
    printf("Ciphertext: ");
    des_print_hex(ciphertext, DES_BLOCK_SIZE);

    // Decrypt
    des_process_block(ciphertext, decrypted, key_sets, DES_DECRYPT);
    printf("Decrypted:  ");
    des_print_hex(decrypted, DES_BLOCK_SIZE);

    // Verify
    if (memcmp(plaintext, decrypted, DES_BLOCK_SIZE) == 0) {
        printf("\n✓ Encryption/Decryption successful! Plaintext matches decrypted text.\n");
    } else {
        printf("\n✗ Encryption/Decryption failed! Plaintext does not match decrypted text.\n");
    }

    printf("\n");

    // Demonstrate with random key
    printf("Example with random key:\n");
    printf("------------------------\n");

    uint8_t random_key[DES_KEY_SIZE];
    des_generate_key(random_key);

    uint8_t random_plaintext[DES_BLOCK_SIZE] = "HELLO!!!";
    uint8_t random_ciphertext[DES_BLOCK_SIZE];
    uint8_t random_decrypted[DES_BLOCK_SIZE];

    printf("Random Key:     ");
    des_print_hex(random_key, DES_KEY_SIZE);

    printf("Plaintext:      ");
    des_print_hex(random_plaintext, DES_BLOCK_SIZE);

    des_generate_subkeys(random_key, key_sets);
    des_process_block(random_plaintext, random_ciphertext, key_sets, DES_ENCRYPT);
    printf("Ciphertext:     ");
    des_print_hex(random_ciphertext, DES_BLOCK_SIZE);

    des_process_block(random_ciphertext, random_decrypted, key_sets, DES_DECRYPT);
    printf("Decrypted:      ");
    des_print_hex(random_decrypted, DES_BLOCK_SIZE);

    printf("As string:      %s\n", random_decrypted);

    return 0;
}
