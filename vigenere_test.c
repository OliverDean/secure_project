#include <stdio.h>
#include <stdlib.h>
#include "crypto.h"  // Include the header where the Vigenère functions are declared

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <range_low> <range_high> <key> <text>\n", argv[0]);
        return 1;
    }

    char range_low = argv[1][0];  // First character of range_low argument
    char range_high = argv[2][0]; // First character of range_high argument
    const char *key = argv[3];
    const char *plain_text = argv[4];

    char *cipher_text = NULL;
    char *decrypted_text = NULL;

    // Perform encryption
    if (vigenere_encrypt(range_low, range_high, key, plain_text, &cipher_text) != 0) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }

    // Perform decryption
    if (vigenere_decrypt(range_low, range_high, key, cipher_text, &decrypted_text) != 0) {
        fprintf(stderr, "Decryption failed\n");
        SAFE_FREE(cipher_text);
        return 1;
    }

    printf("Original: %s\nEncrypted: %s\nDecrypted: %s\n", plain_text, cipher_text, decrypted_text);

    // Free allocated memory
    SAFE_FREE(cipher_text);
    SAFE_FREE(decrypted_text);
    return 0;
}
