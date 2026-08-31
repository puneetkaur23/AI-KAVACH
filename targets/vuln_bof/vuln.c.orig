/*
 * vuln_bof/vuln.c
 * Deliberately vulnerable: CWE-787 Out-of-bounds Write (stack buffer overflow via strcpy)
 * Used for test case D1 / P1
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* VULN: fixed-size buffer, no bounds check on input */
void process_name(const char *input) {
    char buf[64];
    strcpy(buf, input);  /* CWE-787: no length check */
    printf("Hello, %s\n", buf);
}

int read_file_input(const char *path, char *out, size_t max_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(out, 1, max_len, f);
    fclose(f);
    return (int)n;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    char input[4096] = {0};
    int n = read_file_input(argv[1], input, sizeof(input) - 1);
    if (n <= 0) {
        fprintf(stderr, "Failed to read input\n");
        return 1;
    }
    process_name(input);
    return 0;
}
