/*
 * sample_vulnerable_target.c
 * 
 * Standalone test file for AI Kavach Web UI Drag-and-Drop upload.
 * You can drag this file directly into http://localhost:8000/#/analyze
 * 
 * Bug: Stack Buffer Overflow (CWE-121 / CWE-787)
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function(const char *user_input) {
    char stack_buffer[32];
    /* UNSAFE: strcpy has no bounds check */
    strcpy(stack_buffer, user_input);
    printf("Processed input: %s\n", stack_buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        return 1;
    }

    char file_data[1024] = {0};
    size_t bytes_read = fread(file_data, 1, sizeof(file_data) - 1, f);
    fclose(f);

    if (bytes_read > 0) {
        vulnerable_function(file_data);
    }

    return 0;
}
