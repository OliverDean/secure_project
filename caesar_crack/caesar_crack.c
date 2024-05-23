#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define ALPHABET_SIZE 26
#define MAX_OUTPUT_WORDS 50

/**
 * @brief Decrypts a given ciphertext using the Caesar cipher with a specified key.
 *
 * @param key The decryption key (number of positions to shift).
 * @param cipher_text Pointer to the null-terminated string containing the ciphertext to be decrypted.
 * @param plain_text Pointer to the buffer where the decrypted text will be stored. The buffer must be large enough to hold the decrypted text.
 */
void caesar_decrypt(int key, const char *cipher_text, char *plain_text) {
    for (size_t i = 0; i < strlen(cipher_text); i++) {
        if (isalpha(cipher_text[i])) {
            char offset = isupper(cipher_text[i]) ? 'A' : 'a';
            plain_text[i] = ((cipher_text[i] - offset - key + ALPHABET_SIZE) % ALPHABET_SIZE) + offset;
        } else {
            plain_text[i] = cipher_text[i];
        }
    }
    plain_text[strlen(cipher_text)] = '\0';
}

/**
 * @brief Calculates the English score of a given text based on letter frequencies.
 *
 * @param text Pointer to the null-terminated string containing the text to analyze.
 * @return The calculated English score of the text.
 *
 * The score is calculated by comparing the frequency of each letter in the text to the known frequencies of letters in the English language.
 */
double calculate_english_score(const char *text) {
    double frequencies[ALPHABET_SIZE] = {
        8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094,
        6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929,
        0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150,
        1.974, 0.074
    };
    double score = 0.0;
    int counts[ALPHABET_SIZE] = {0};
    int total_chars = 0;

    for (size_t i = 0; i < strlen(text); i++) {
        if (isalpha(text[i])) {
            counts[tolower(text[i]) - 'a']++;
            total_chars++;
        }
    }

    for (int i = 0; i < ALPHABET_SIZE; i++) {
        double frequency = (double)counts[i] / total_chars * 100;
        score += frequencies[i] * frequency;
    }

    return score;
}

/**
 * @brief Prints the first n words of a given text.
 *
 * @param text Pointer to the null-terminated string containing the text to print.
 * @param n The number of words to print.
 */
void print_first_n_words(const char *text, int n) {
    int word_count = 0;
    for (size_t i = 0; i < strlen(text); i++) {
        if (isspace(text[i])) {
            word_count++;
        }
        if (word_count >= n) {
            printf("\n");
            return;
        }
        putchar(text[i]);
    }
    printf("\n");
}

/**
 * @brief Attempts to crack a Caesar cipher by trying all possible keys and choosing the best result based on English letter frequencies.
 *
 * @param cipher_text Pointer to the null-terminated string containing the ciphertext to crack.
 *
 * This function finds the best decryption key by scoring the decrypted text with each possible key and choosing the one with the highest score.
 */
void crack_caesar_cipher(const char *cipher_text) {
    size_t len = strlen(cipher_text);
    char *best_plain_text = malloc(len + 1);
    if (!best_plain_text) {
        perror("Failed to allocate memory");
        exit(1);
    }
    double best_score = 0.0;
    int best_key = 0;

    for (int key = 0; key < ALPHABET_SIZE; key++) {
        char *plain_text = malloc(len + 1);
        if (!plain_text) {
            perror("Failed to allocate memory");
            free(best_plain_text);
            exit(1);
        }
        caesar_decrypt(key, cipher_text, plain_text);
        double score = calculate_english_score(plain_text);

        if (score > best_score) {
            best_score = score;
            best_key = key;
            strcpy(best_plain_text, plain_text);
        }

        free(plain_text);
    }

    printf("Best rotation: %d\n", best_key);
    printf("Probability score: %.2f\n", best_score);
    printf("First %d words of decrypted output:\n", MAX_OUTPUT_WORDS);
    print_first_n_words(best_plain_text, MAX_OUTPUT_WORDS);

    free(best_plain_text);
}

/**
 * @brief Prints usage information for the program.
 *
 * This function prints the correct usage of the program and provides examples of the expected output.
 */
void print_usage() {
    printf("Usage: caesar_cracker <ciphertext_file>\n");
    printf("Attempts to crack a Caesar cipher by trying all possible keys.\n\n");
    printf("Expected output:\n");
    printf("Best rotation: <key>\n");
    printf("Probability score: <score>\n");
    printf("First %d words of decrypted output:\n", MAX_OUTPUT_WORDS);
    printf("<decrypted text>\n");
}

/**
 * @brief Main function for the Caesar cipher cracker program.
 *
 * @param argc The number of command-line arguments.
 * @param argv The array of command-line arguments.
 * @return 0 if the program completes successfully, 1 otherwise.
 *
 * This function reads a ciphertext from a file, attempts to crack it using a Caesar cipher, and prints the results.
 * If the -h flag is provided, it prints usage information.
 */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        print_usage();
        return 1;
    }

    if (strcmp(argv[1], "-h") == 0) {
        print_usage();
        return 0;
    }

    FILE *file = fopen(argv[1], "r");
    if (!file) {
        perror("Failed to open file");
        return 1;
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *cipher_text = malloc(length + 1);
    if (!cipher_text) {
        perror("Failed to allocate memory");
        fclose(file);
        return 1;
    }

    fread(cipher_text, 1, length, file);
    cipher_text[length] = '\0';
    fclose(file);

    crack_caesar_cipher(cipher_text);
    free(cipher_text);

    return 0;
}
