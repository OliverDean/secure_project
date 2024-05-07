#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "crypto.h"  // Assuming macros are defined in this header

// Function prototypes
void test_log_error();
int test_check_macro();
int test_safe_alloc();
void test_safe_free();

int main() {
    // Test each macro's behavior
    test_log_error();

    if (test_check_macro() != 0) {
        fprintf(stderr, "Check macro test failed.\n");
    }

    if (test_safe_alloc() != 0) {
        fprintf(stderr, "Safe alloc test failed.\n");
    }

    test_safe_free();

    return 0;
}

void test_log_error() {
    // This function tests the LOG_ERROR macro by forcing an error message
    LOG_ERROR("This is a test error message without parameters.");
    LOG_ERROR("This is a test error message with one parameter: %d", -1);
}

int test_check_macro() {
    // This function tests the CHECK macro by intentionally failing a condition
    int value = 0;
    CHECK(value == 1, -1, "Failed because value is not 1, value is %d", value);
    return 0; // Return 0 to indicate success if the macro does not trigger
}

int test_safe_alloc() {
    // This function tests the SAFE_ALLOC macro by trying to allocate too much memory
    char *large_memory_block;
    size_t large_size = SIZE_MAX;  // Intentionally large size to force failure
    SAFE_ALLOC(large_memory_block, large_size);  // This should fail and trigger the log error

    SAFE_FREE(large_memory_block);  // Proper cleanup
    return 0;  // Return 0 to indicate success if SAFE_ALLOC does not fail
}

void test_safe_free() {
    // This function tests SAFE_FREE by allocating and then correctly freeing memory
    char *buffer = malloc(100);
    if (buffer != NULL) {
        memset(buffer, 0, 100);  // Use the buffer for some operations
    }

    // Now safely free the buffer
    SAFE_FREE(buffer);
    if (buffer == NULL) {
        printf("Buffer successfully freed.\n");
    }
    // Attempt to free an already NULL pointer (should not do anything harmful)
    SAFE_FREE(buffer);
}
