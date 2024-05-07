#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>

#include "crypto.h"

int caesar_encrypt(char range_low, char range_high, int key, const char *plain_text, char **cipher_text) {
    CHECK(plain_text != NULL && cipher_text != NULL && range_high > range_low, -1, "Invalid input parameters");

    size_t len = strlen(plain_text);
    SAFE_ALLOC(*cipher_text, len + 1);
    int range_size = range_high - range_low + 1;

    if (key < 0 || key > range_size) {
        LOG_ERROR("Key %d is out of valid range [0, %d]", key, range_size);
        return -1;
    }

    for (size_t i = 0; i < len; i++) {
        if (plain_text[i] >= range_low && plain_text[i] <= range_high) {
            int offset = plain_text[i] - range_low;
            (*cipher_text)[i] = (offset + key) % range_size + range_low;
        } else {
            (*cipher_text)[i] = plain_text[i];
        }
    }
    (*cipher_text)[len] = '\0';
    return 0;
}

int caesar_decrypt(char range_low, char range_high, int key, const char *cipher_text, char **plain_text) {
    return caesar_encrypt(range_low, range_high, -key, cipher_text, plain_text);
}

int vigenere_encrypt(char range_low, char range_high, const char *key, const char *plain_text, char **cipher_text) {
    CHECK(plain_text != NULL && key != NULL && range_high > range_low && key[0] != '\0', -1);

    // Check if all characters in the key are within the valid range
    for (size_t i = 0; key[i] != '\0'; i++) {
        if (key[i] < range_low || key[i] > range_high) {
            fprintf(stderr, "Error: Key character '%c' out of range [%c, %c]\n", key[i], range_low, range_high);
            return -3;  // Return error if key is out of the character range
        }
    }

    size_t len = strlen(plain_text);
    size_t key_len = strlen(key);
    SAFE_ALLOC(*cipher_text, len + 1);

    int range_size = range_high - range_low + 1;
    for (size_t i = 0, key_index = 0; i < len; i++) {
        if (plain_text[i] >= range_low && plain_text[i] <= range_high) {
            int plain_offset = plain_text[i] - range_low;
            int key_offset = key[key_index % key_len] - range_low;
            (*cipher_text)[i] = (plain_offset + key_offset) % range_size + range_low;
            key_index++;
        } else {
            (*cipher_text)[i] = plain_text[i];
        }
    }
    (*cipher_text)[len] = '\0';

    // Debugging output
    fprintf(stderr, "Debug: Vigenere encryption completed. Input: '%s', Key: '%s', Output: '%s'\n",
            plain_text, key, *cipher_text);

    return 0;
}

int vigenere_decrypt(char range_low, char range_high, const char *key, const char *cipher_text, char **plain_text) {
    CHECK(cipher_text != NULL && key != NULL && range_high > range_low && key[0] != '\0', -1);

    // Check if all characters in the key are within the valid range
    for (size_t i = 0; key[i] != '\0'; i++) {
        if (key[i] < range_low || key[i] > range_high) {
            fprintf(stderr, "Error: Key character '%c' out of range [%c, %c]\n", key[i], range_low, range_high);
            return -3;  // Return error if key is out of the character range
        }
    }

    size_t len = strlen(cipher_text);
    size_t key_len = strlen(key);
    SAFE_ALLOC(*plain_text, len + 1);

    int range_size = range_high - range_low + 1;
    for (size_t i = 0, key_index = 0; i < len; i++) {
        if (cipher_text[i] >= range_low && cipher_text[i] <= range_high) {
            int cipher_offset = cipher_text[i] - range_low;
            int key_offset = key[key_index % key_len] - range_low;
            (*plain_text)[i] = (cipher_offset - key_offset + range_size) % range_size + range_low;
            key_index++;
        } else {
            (*plain_text)[i] = cipher_text[i];
        }
    }
    (*plain_text)[len] = '\0';
    return 0;
}