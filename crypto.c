/**
 * @file crypto.c
 * @brief Implementation of Caesar and Vigenere cipher encryption and decryption functions.
 * 
 * This file contains functions for encrypting and decrypting text using
 * Caesar and Vigenere ciphers.
 * 
 * @author 
 * Oliver Dean 21307131
 * 
 * @bug No known bugs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "crypto.h"

/**
 * @brief Encrypts text using the Caesar cipher.
 * 
 * @param range_low The lower bound of the character range.
 * @param range_high The upper bound of the character range.
 * @param key The encryption key.
 * @param plain_text The input plain text.
 * @param cipher_text The output cipher text.
 * 
 * The Caesar cipher shifts each character in the plain text by a fixed number of
 * positions defined by the key. The character range is specified by range_low and range_high.
 * The function assumes the input text contains characters within the specified range.
 */
void caesar_encrypt(char range_low, char range_high, int key, const char *plain_text, char *cipher_text) {
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

/**
 * @brief Decrypts text using the Caesar cipher.
 * 
 * @param range_low The lower bound of the character range.
 * @param range_high The upper bound of the character range.
 * @param key The decryption key.
 * @param cipher_text The input cipher text.
 * @param plain_text The output plain text.
 * 
 * This function uses the caesar_encrypt function with a negative key to decrypt
 * the input cipher text.
 */
void caesar_decrypt(char range_low, char range_high, int key, const char *cipher_text, char *plain_text) {
    caesar_encrypt(range_low, range_high, -key, cipher_text, plain_text);
}

/**
 * @brief Encrypts text using the Vigenere cipher.
 * 
 * @param range_low The lower bound of the character range.
 * @param range_high The upper bound of the character range.
 * @param key The encryption key.
 * @param plain_text The input plain text.
 * @param cipher_text The output cipher text.
 * 
 * The Vigenere cipher uses a keyword to encrypt the text. Each character in the plain text
 * is shifted by a number of positions defined by the corresponding character in the key.
 * The character range is specified by range_low and range_high. The function assumes the input text
 * contains characters within the specified range.
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

/**
 * @brief Decrypts text using the Vigenere cipher.
 * 
 * @param range_low The lower bound of the character range.
 * @param range_high The upper bound of the character range.
 * @param key The decryption key.
 * @param cipher_text The input cipher text.
 * @param plain_text The output plain text.
 * 
 * The Vigenere cipher uses a keyword to decrypt the text. Each character in the cipher text
 * is shifted by a number of positions defined by the corresponding character in the key, in the reverse direction.
 * The character range is specified by range_low and range_high. The function assumes the input text
 * contains characters within the specified range.
 */
void vigenere_decrypt(char range_low, char range_high, const char *key, const char *cipher_text, char *plain_text) {
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
