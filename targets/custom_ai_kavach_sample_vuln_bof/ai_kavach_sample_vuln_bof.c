/*
 * AI Kavach intentionally vulnerable test target.
 * Expected: CWE-121 Stack-based Buffer Overflow.
 * For local security testing only.
 */

#include <stdio.h>
#include <string.h>

static void copy_input(const char *input)
{
    char buffer[16];

    /* INTENTIONAL VULNERABILITY: unbounded copy into stack buffer */
    strcpy(buffer, input);

    printf("Received: %s\n", buffer);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    copy_input(argv[1]);
    return 0;
}
