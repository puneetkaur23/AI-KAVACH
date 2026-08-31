/*
 * clean_target/clean.c
 * No injected vulnerabilities. Used for false-positive testing (test case D4).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_NAME 64

void process_name(const char *input) {
    char buf[MAX_NAME];
    /* SAFE: strncpy with explicit limit */
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    printf("Hello, %s\n", buf);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    char input[MAX_NAME] = {0};
    size_t n = fread(input, 1, sizeof(input) - 1, f);
    fclose(f);
    if (n == 0) return 1;
    process_name(input);
    return 0;
}
