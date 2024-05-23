/**
 * @file cli.c
 * @brief Command-line interface for Caesar and Vigenere cipher encryption and decryption.
 * 
 * This file contains the main function for handling command-line arguments
 * and performing encryption or decryption using Caesar or Vigenere ciphers.
 * 
 * @author 
 * Oliver Dean 21307131
 * 
 * @bug No known bugs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include "crypto.h"


int isValidInteger(const char *str);

int isKeyValidForRange(const char *key, char low, char high);

/**
 * @brief Main function for the command-line interface.
 *
 * @param argc The number of command-line arguments.
 * @param argv The array of command-line arguments.
 * @return 0 if the program completes successfully, non-zero otherwise.
 *
 * This function handles command-line arguments to perform encryption or decryption
 * using Caesar or Vigenere ciphers. The user must provide the operation type,
 * the key, and the message as arguments.
 * 
 * Usage: <operation> <key> <message>
 * - operation: "caesar-encrypt", "caesar-decrypt", "vigenere-encrypt", "vigenere-decrypt"
 * - key: The encryption/decryption key
 * - message: The input message to encrypt or decrypt
 * 
 * \pre `argc` must be 4.
 * \pre `argv` must contain valid strings for the operation, key, and message.
 */
int cli(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <operation> <key> <message>\n", argv[0]);
        return 1;
    }

    const char *operation = argv[1];
    const char *key_text = argv[2];
    const char *message = argv[3];

    // Allocate memory for the result dynamically
    size_t message_length = strlen(message);
    char *result = (char *)malloc(message_length + 1);
    if (result == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        return 1;
    }

    // Validate the operation type and key format
    if (strcmp(operation, "caesar-encrypt") == 0 || strcmp(operation, "caesar-decrypt") == 0) {
        if (!isValidInteger(key_text)) {
            fprintf(stderr, "Invalid key: Caesar cipher key must be a valid integer.\n");
            free(result);
            return 1;
        }
        int key = atoi(key_text);  // Convert key to integer

        // Validate key range for Caesar cipher
        int range_size = 'Z' - 'A' + 1;
        if (key < 0 || key >= range_size) {
            fprintf(stderr, "Key %d is out of valid range [0, %d]\n", key, range_size - 1);
            free(result);
            return 1;
        }

        if (strcmp(operation, "caesar-encrypt") == 0) {
            caesar_encrypt('A', 'Z', key, message, result);
        } else {
            caesar_decrypt('A', 'Z', key, message, result);
        }
    } else if (strcmp(operation, "vigenere-encrypt") == 0 || strcmp(operation, "vigenere-decrypt") == 0) {
        if (!isKeyValidForRange(key_text, 'A', 'Z')) {
            fprintf(stderr, "Key contains invalid characters for the specified range.\n");
            free(result);
            return 1;
        }

        if (strcmp(operation, "vigenere-encrypt") == 0) {
            vigenere_encrypt('A', 'Z', key_text, message, result);
        } else {
            vigenere_decrypt('A', 'Z', key_text, message, result);
        }
    } else {
        fprintf(stderr, "Invalid operation. Use 'caesar-encrypt', 'caesar-decrypt', 'vigenere-encrypt', or 'vigenere-decrypt'.\n");
        free(result);
        return 1;
    }

    // Print the result to standard output and return 0 for success
    printf("%s\n", result);
    free(result);
    return 0;
}

/**
 * @brief Validates if the input is a valid integer.
 *
 * @param str Pointer to the string to validate.
 * @return 0 if the string is a valid integer, 1 otherwise.
 */
int isValidInteger(const char *str) {
    if (str == NULL)
        return 0;

    while (isspace(*str)) str++;

    if (*str == '+' || *str == '-') str++;

    if (!isdigit(*str))
        return 0;

    while (isdigit(*str)) str++;

    while (isspace(*str)) str++;

    return *str == '\0';
}

/**
 * @brief Validates if the key contains characters within the specified range.
 *
 * @param key Pointer to the string key to validate.
 * @param low The lower bound of the character range.
 * @param high The upper bound of the character range.
 * @return 0 if the key is valid for the specified range, 1 otherwise.
 */
int isKeyValidForRange(const char *key, char low, char high) {
    for (size_t i = 0; key[i] != '\0'; i++) {
        if (key[i] < low || key[i] > high) return 0;
    }
    return 1;
}
