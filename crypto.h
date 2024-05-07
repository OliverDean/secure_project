#ifndef CRYPTO_H
#define CRYPTO_H

// Logging macro for debugging and auditing
#define LOG_ERROR(fmt, ...) fprintf(stderr, "[ERROR] %s: " fmt "\n", __func__, ##__VA_ARGS__)

// Error checking macro that can handle an optional message
#define CHECK(cond, err_code, ...) do { \
    if (!(cond)) { \
        LOG_ERROR("Condition failed: %s", #cond); \
        LOG_ERROR(__VA_ARGS__); \
        return err_code; \
    } \
} while (0)

// Macro for safe memory allocation with a fallback message if no message is provided
#define SAFE_ALLOC(ptr, size) do { \
    (ptr) = malloc(size); \
    if (!(ptr)) { \
        LOG_ERROR("Failed to allocate memory"); \
        return -2; \
    } \
} while (0)

// Macro to safely free memory and set the pointer to NULL
#define SAFE_FREE(ptr) do { if ((ptr)) { free(ptr); (ptr) = NULL; } } while (0)

// Function declarations
int caesar_encrypt(char range_low, char range_high, int key, const char *plain_text, char **cipher_text);
int caesar_decrypt(char range_low, char range_high, int key, const char *cipher_text, char **plain_text);
int vigenere_encrypt(char range_low, char range_high, const char *key, const char *plain_text, char **cipher_text);
int vigenere_decrypt(char range_low, char range_high, const char *key, const char *cipher_text, char **plain_text);

#endif // CRYPTO_H
