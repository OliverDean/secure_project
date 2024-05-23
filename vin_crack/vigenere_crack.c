#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <stdbool.h>

#define MAX_KEY_LENGTH 10
#define ALPHABET_SIZE 26
#define MIN_KEY_LENGTH 1
#define GOOD_ENOUGH_THRESHOLD 100

double english_frequencies[ALPHABET_SIZE] = {
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094,
    6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929,
    0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150,
    1.974, 0.074
};

/**
 * @brief Duplicates a string.
 *
 * @param s Pointer to the null-terminated string to duplicate.
 * @return Pointer to the duplicated string, or NULL if memory allocation fails.
 */
char *strdup_custom(const char *s) {
    size_t len = strlen(s) + 1;
    char *dup = malloc(len);
    if (dup) {
        strcpy(dup, s);
    }
    return dup;
}

/**
 * @brief Compares two strings ignoring case.
 *
 * @param s1 Pointer to the first null-terminated string to compare.
 * @param s2 Pointer to the second null-terminated string to compare.
 * @return An integer less than, equal to, or greater than zero if s1 (ignoring case)
 *         is found to be less than, to match, or be greater than s2, respectively.
 */
int strcasecmp_custom(const char *s1, const char *s2) {
    while (*s1 && *s2) {
        if (tolower((unsigned char)*s1) != tolower((unsigned char)*s2)) {
            return tolower((unsigned char)*s1) - tolower((unsigned char)*s2);
        }
        s1++;
        s2++;
    }
    return tolower((unsigned char)*s1) - tolower((unsigned char)*s2);
}

/**
 * @brief Decrypts a given ciphertext using the Vigenere cipher with a specified key.
 *
 * @param key Pointer to the null-terminated string containing the encryption key.
 * @param cipher_text Pointer to the null-terminated string containing the ciphertext to be decrypted.
 * @param plain_text Pointer to the buffer where the decrypted text will be stored.
 */
void vigenere_decrypt(const char *key, const char *cipher_text, char *plain_text) {
    size_t key_len = strlen(key);
    for (size_t i = 0, j = 0; i < strlen(cipher_text); i++) {
        if (isalpha(cipher_text[i])) {
            char offset = isupper(cipher_text[i]) ? 'A' : 'a';
            char key_offset = isupper(key[j % key_len]) ? 'A' : 'a';
            plain_text[i] = ((cipher_text[i] - offset - (key[j % key_len] - key_offset) + ALPHABET_SIZE) % ALPHABET_SIZE) + offset;
            j++;
        } else {
            plain_text[i] = cipher_text[i];
        }
    }
    plain_text[strlen(cipher_text)] = '\0';
}

/**
 * @brief Calculates the chi-square statistic for a given text based on English letter frequencies.
 *
 * @param text Pointer to the null-terminated string containing the text to analyze.
 * @return The chi-square statistic.
 */
double calculate_chi_square(const char *text) {
    static struct {
        char *text;
        double chi_square;
    } cache[10000] = {{NULL, 0.0}};
    static int cache_size = 0;

    for (int i = 0; i < cache_size; ++i) {
        if (strcmp(cache[i].text, text) == 0) {
            return cache[i].chi_square;
        }
    }

    int counts[ALPHABET_SIZE] = {0};
    int total_chars = 0;

    for (size_t i = 0; i < strlen(text); i++) {
        if (isalpha(text[i])) {
            counts[tolower(text[i]) - 'a']++;
            total_chars++;
        }
    }

    double chi_square = 0.0;
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        double expected = english_frequencies[i] * total_chars / 100;
        double observed = counts[i];
        if (expected > 0) {
            chi_square += pow(observed - expected, 2) / expected;
        }
    }

    if (cache_size < 1000) {
        cache[cache_size].text = strdup_custom(text);
        cache[cache_size].chi_square = chi_square;
        cache_size++;
    }

    return chi_square;
}

/**
 * @brief Generates all possible keys of a given length and finds the best key for decrypting the ciphertext.
 *
 * @param key Pointer to the buffer where the current key is being built.
 * @param position The current position in the key being generated.
 * @param max_length The maximum length of the keys to generate.
 * @param cipher_text Pointer to the null-terminated string containing the ciphertext to decrypt.
 * @param best_key Pointer to the buffer where the best key will be stored.
 * @param best_plain_text Pointer to the buffer where the decrypted text will be stored.
 * @param best_chi_square Pointer to the variable holding the best chi-square value found so far.
 */
void generate_keys(char *key, int position, int max_length, const char *cipher_text, char *best_key, char *best_plain_text, double *best_chi_square, bool *found_good_enough) {
    if (*found_good_enough) return;

    if (position == max_length) {
        key[position] = '\0';
        char *plain_text = malloc(strlen(cipher_text) + 1);
        vigenere_decrypt(key, cipher_text, plain_text);
        double chi_square = calculate_chi_square(plain_text);

        if (chi_square < *best_chi_square) {
            *best_chi_square = chi_square;
            strcpy(best_key, key);
            strcpy(best_plain_text, plain_text);
        }

        if (chi_square < GOOD_ENOUGH_THRESHOLD) {
            *found_good_enough = true;
        }

        free(plain_text);
        return;
    }

    for (char c = 'A'; c <= 'Z'; c++) {
        key[position] = c;
        generate_keys(key, position + 1, max_length, cipher_text, best_key, best_plain_text, best_chi_square, found_good_enough);
        if (*found_good_enough) return;
    }
}

/**
 * @brief Finds the best key for decrypting the ciphertext using brute force.
 *
 * @param cipher_text Pointer to the null-terminated string containing the ciphertext to decrypt.
 * @param best_key Pointer to the buffer where the best key will be stored.
 * @param best_plain_text Pointer to the buffer where the decrypted text will be stored.
 */
void find_best_key_brute_force(const char *cipher_text, char *best_key, char *best_plain_text) {
    double best_chi_square = INFINITY;
    char key[MAX_KEY_LENGTH + 1] = {0};
    bool found_good_enough = false;

    for (int key_length = MIN_KEY_LENGTH; key_length <= MAX_KEY_LENGTH; key_length++) {
        generate_keys(key, 0, key_length, cipher_text, best_key, best_plain_text, &best_chi_square, &found_good_enough);
        if (found_good_enough) break;
    }
}

/**
 * @brief Validates the output by counting valid words in the decrypted text.
 *
 * @param plain_text Pointer to the null-terminated string containing the decrypted text to validate.
 */
void validate_output(const char *plain_text) {
    int valid_word_count = 0;
    const char *dictionary[] = {
        "THE", "BE", "TO", "OF", "AND", "A", "IN", "THAT", "HAVE", "I"
    };
    int dict_size = sizeof(dictionary) / sizeof(dictionary[0]);

    char *text_copy = strdup_custom(plain_text);
    char *token = strtok(text_copy, " \n");

    while (token != NULL) {
        for (int i = 0; i < dict_size; i++) {
            if (strcasecmp_custom(token, dictionary[i]) == 0) {
                valid_word_count++;
            }
        }
        token = strtok(NULL, " \n");
    }

    free(text_copy);
    printf("Valid words found: %d\n", valid_word_count);
}

/**
 * @brief Main function for the program.
 *
 * @param argc The number of command-line arguments.
 * @param argv The array of command-line arguments.
 * @return EXIT_SUCCESS if the program completes successfully, EXIT_FAILURE otherwise.
 *
 * This function reads a ciphertext from a file, finds the best key using brute force, 
 * decrypts the ciphertext, and validates the output.
 */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <ciphertext_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    FILE *file = fopen(argv[1], "r");
    if (!file) {
        perror("Failed to open file");
        return EXIT_FAILURE;
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *cipher_text = (char *)malloc(length + 1);
    if (!cipher_text) {
        perror("Failed to allocate memory");
        fclose(file);
        return EXIT_FAILURE;
    }

    fread(cipher_text, 1, length, file);
    cipher_text[length] = '\0';
    fclose(file);

    char *best_plain_text = (char *)malloc(length + 1);
    if (!best_plain_text) {
        perror("Failed to allocate memory");
        free(cipher_text);
        return EXIT_FAILURE;
    }

    char best_key[MAX_KEY_LENGTH + 1] = {0};

    find_best_key_brute_force(cipher_text, best_key, best_plain_text);

    printf("Best key: %s\n", best_key);
    printf("Decrypted output:\n%s\n", best_plain_text);

    validate_output(best_plain_text);

    free(best_plain_text);
    free(cipher_text);

    return EXIT_SUCCESS;
}
