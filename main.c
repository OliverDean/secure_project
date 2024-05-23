#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>

#include "crypto.h"

int main(int argc, char **argv) {
    // Pass command-line arguments to the 'cli' function
    int result = cli(argc, argv);

    return result;
}