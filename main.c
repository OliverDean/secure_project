#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>

#include "crypto.h"


int main() {
    const char *plain_text = "HELLOWORLD";
    char *cipher_text = NULL;

    // Example: Encrypt using Caesar cipher
    int error = caesar_encrypt('A', 'Z', 3, plain_text, &cipher_text);
    if (error != 0) {
        fprintf(stderr, "Encryption failed with error code %d\n", error);
        return error;
    }

    printf("Encrypted Text: %s\n", cipher_text);

    // Decrypt the text
    char *decrypted_text = NULL;
    error = caesar_decrypt('A', 'Z', 3, cipher_text, &decrypted_text);
    if (error != 0) {
        fprintf(stderr, "Decryption failed with error code %d\n", error);
        SAFE_FREE(cipher_text);
        return error;
    }

    printf("Decrypted Text: %s\n", decrypted_text);

    // Free the allocated memory
    SAFE_FREE(cipher_text);
    SAFE_FREE(decrypted_text);

    return 0;
}
