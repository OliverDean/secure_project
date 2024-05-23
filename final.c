#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include "crypto.h"

int isValidInteger(const char *str);

int isKeyValidForRange(const char *key, char low, char high);

/** Encrypt a given plaintext using the Caesar cipher, using a specified key, where the
  * characters to encrypt fall within a given range (and all other characters are copied
  * over unchanged).
  *
  * Each character in `plain_text` is examined to see if it falls with the range specified
  * by `range_low` and `range_high`, and a corresponding character is then written to the
  * same position in `cipher_text`. If the `plain_text` character is outside the range,
  * then the corresponding character is not encrypted: exactly the same character should
  * be written to exactly the same position in `cipher_text`. If the `plain_text`
  * character is within the range, it should be encrypted using the Caesar cipher:  
  * a new character is obtained by shifting it by `key` positions (modulo the size of the
  * range).
  *
  * For decryption, use a negative key value or use the `caesar_decrypt` function with the
  * same key value.
  *
  *
  * ## Example usage
  *
  *
  *
  * ```c
  *   char plain_text[] = "HELLOWORLD";
  *   char cipher_text[sizeof(plain_text)] = {0};
  *   caesar_encrypt('A', 'Z', 3, plain_text, cipher_text);
  *   // After the function call, cipher_text will contain the encrypted text
  *   char expected_cipher_text = "KHOORZRUOG"
  *   assert(strcmp(cipher_text, expected_cipher_text) == 0);
  * ```
  *
  * \param range_low A character representing the lower bound of the character range to be
  *           encrypted
  * \param range_high A character representing the upper bound of the character range
  * \param key The encryption key
  * \param plain_text A null-terminated string containing the plaintext to be encrypted
  * \param cipher_text A pointer to a buffer where the encrypted text will be stored. The
  *           buffer must be large enough to hold a C string of the same length as
  *           plain_text (including the terminating null character).
  *
  * \pre `plain_text` must be a valid null-terminated C string
  * \pre `cipher_text` must point to a buffer of identical length to `plain_text`
  * \pre `range_high` must be strictly greater than `range_low`.
  * \pre `key` must fall within range from 0 to `(range_high - range_low)`, inclusive.
  */
void caesar_encrypt(char range_low, char range_high, int key, const char * plain_text, char * cipher_text) {
    assert(plain_text != NULL && cipher_text != NULL);
    assert(range_high > range_low);
    size_t len = strlen(plain_text);
    int range_size = range_high - range_low + 1;
    
    // Normalize key to be within the valid range
    key = (key % range_size + range_size) % range_size;
    assert(key >= 0 && key < range_size);
    
    for (size_t i = 0; i < len; i++) {
        if (plain_text[i] >= range_low && plain_text[i] <= range_high) {
            int offset = plain_text[i] - range_low;
            cipher_text[i] = (offset + key) % range_size + range_low;
        } else {
            cipher_text[i] = plain_text[i];
        }
    }
    cipher_text[len] = '\0';
}


/** Decrypt a given ciphertext using the Caesar cipher, using a specified key, where the
  * characters to decrypt fall within a given range (and all other characters are copied
  * over unchanged).
  *
  * Calling `caesar_decrypt` with some key $n$ is exactly equivalent to calling
  * `caesar_encrypt` with the key $-n$.
  *
  * \param range_low A character representing the lower bound of the character range to be
  *           encrypted
  * \param range_high A character representing the upper bound of the character range
  * \param key The encryption key
  * \param cipher_text A null-terminated string containing the ciphertext to be decrypted
  * \param plain_text A pointer to a buffer where the decrypted text will be stored. The
  *           buffer must be large enough to hold a C string of the same length as
  *           cipher_text (including the terminating null character).
  *
  * \pre `cipher_text` must be a valid null-terminated C string
  * \pre `plain_text` must point to a buffer of identical length to `cipher_text`
  * \pre `range_high` must be strictly greater than `range_low`.
  * \pre `key` must fall within range from 0 to `(range_high - range_low)`, inclusive.
  */
void caesar_decrypt(char range_low, char range_high, int key, const char * cipher_text, char * plain_text) {
    caesar_encrypt(range_low, range_high, -key, cipher_text, plain_text);
}

/** Encrypt a given plaintext using the Vigenere cipher, using a specified key, where the
  * characters to encrypt fall within a given range (and all other characters are copied
  * over unchanged).
  *
  * Each character in `plain_text` is examined to see if it falls with the range specified
  * by `range_low` and `range_high`, and a corresponding character is then written to the
  * same position in `cipher_text`. If the `plain_text` character is outside the range,
  * then the corresponding character is not encrypted: exactly the same character should
  * be written to exactly the same position in `cipher_text`. If the `plain_text`
  * character is within the range, it should be encrypted using the Vigenere cipher.
  * The function maintains an index into `key`, and uses the "current key character"
  * to encrypt. This index starts at position 0, and increments whenever an in-range
  * plaintext character is encountered. (In other words, out-of-range characters do
  * not result in a change of Caesar cipher.)
  *
  * \param range_low A character representing the lower bound of the character range to be
  *           encrypted
  * \param range_high A character representing the upper bound of the character range
  * \param key A null-terminated string containing the encryption key
  * \param plain_text A null-terminated string containing the plaintext to be encrypted
  * \param cipher_text A pointer to a buffer where the encrypted text will be stored. The
  *           buffer must be large enough to hold a C string of the same length as
  *           plain_text (including the terminating null character).
  *
  * \pre `plain_text` must be a valid null-terminated C string
  * \pre `cipher_text` must point to a buffer of identical length to `plain_text`
  * \pre `range_high` must be strictly greater than `range_low`.
  * \pre `key` must not be an empty string.
  */
void vigenere_encrypt(char range_low, char range_high, const char *key, const char *plain_text, char *cipher_text) {
    assert(plain_text != NULL && cipher_text != NULL);
    assert(key != NULL && key[0] != '\0');
    assert(range_high > range_low);
    size_t len = strlen(plain_text);
    size_t key_len = strlen(key);
    int range_size = range_high - range_low + 1;
    for (size_t i = 0, key_index = 0; i < len; i++) {
        if (plain_text[i] >= range_low && plain_text[i] <= range_high) {
            int plain_offset = plain_text[i] - range_low;
            int key_offset = key[key_index % key_len] - range_low;
            cipher_text[i] = (plain_offset + key_offset) % range_size + range_low;
            key_index++;
        } else {
            cipher_text[i] = plain_text[i];
        }
    }
    cipher_text[len] = '\0';
}

/** Decrypt a given ciphertext using the Vigenere cipher, using a specified key, where the
  * characters to decrypt fall within a given range (and all other characters are copied
  * over unchanged).
  *
  * Calling `vigenere_decrypt` with some key $k$ should exactly reverse the operation of
  * `vigenere_encrypt` when called with the same key.
  *
  * \param range_low A character representing the lower bound of the character range to be
  *           decrypted
  * \param range_high A character representing the upper bound of the character range
  * \param key A null-terminated string containing the encryption key
  * \param cipher_text A null-terminated string containing the ciphertext to be decrypted
  * \param plain_text A pointer to a buffer where the decrypted text will be stored. The
  *           buffer must be large enough to hold a C string of the same length as
  *           cipher_text (including the terminating null character).
  *
  * \pre `cipher_text` must be a valid null-terminated C string
  * \pre `plain_text` must point to a buffer of identical length to `cipher_text`
  * \pre `range_high` must be strictly greater than `range_low`.
  * \pre `key` must not be an empty string.
  */
void vigenere_decrypt(char range_low, char range_high, const char * key, const char * cipher_text, char * plain_text) {
    assert(cipher_text != NULL && plain_text != NULL);
    assert(key != NULL && key[0] != '\0');
    assert(range_high > range_low);
    size_t len = strlen(cipher_text);
    size_t key_len = strlen(key);
    int range_size = range_high - range_low + 1;
    for (size_t i = 0, key_index = 0; i < len; i++) {
        if (cipher_text[i] >= range_low && cipher_text[i] <= range_high) {
            int cipher_offset = cipher_text[i] - range_low;
            int key_offset = key[key_index % key_len] - range_low;
            plain_text[i] = (cipher_offset - key_offset + range_size) % range_size + range_low;
            key_index++;
        } else {
            plain_text[i] = cipher_text[i];
        }
    }
    plain_text[len] = '\0';
}

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
        return 1;

    while (isspace(*str)) str++;

    if (*str == '+' || *str == '-') str++;

    if (!isdigit(*str))
        return 1;

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
 * @return 1 if the key is not valid for the specified range, 0 otherwise.
 */
int isKeyValidForRange(const char *key, char low, char high) {
    for (size_t i = 0; key[i] != '\0'; i++) {
        if (key[i] < low || key[i] > high) return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    // Pass command-line arguments to the 'cli' function
    int result = cli(argc, argv);

    return result;
}