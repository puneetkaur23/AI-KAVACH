/*
 * vulnerable_demo.c
 * 
 * Demonstrates a classic memory corruption vulnerability:
 * CWE-121 / CWE-787: Stack-based Buffer Overflow via unsafe strcpy()
 * 
 * Test target for AI Kavach Autonomous Cyber-Reasoning System.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT_SIZE 2048

/*
 * VULNERABLE FUNCTION:
 * Copies input string of arbitrary length into a fixed-size 32-byte stack buffer.
 */
void process_user_profile(const char *user_input) {
    char username_buffer[32];
    
    /* VULNERABILITY (CWE-121 / CWE-787):
     * Unbounded strcpy into 32-byte buffer.
     * Flagged by Semgrep rule: kavach-strcpy-bof
     * Crashes in AddressSanitizer when user_input >= 32 bytes.
     */
    strcpy(username_buffer, user_input);
    
    printf("[+] Profile loaded for user: %s\n", username_buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        fprintf(stderr, "[-] Error: Cannot open input file %s\n", argv[1]);
        return 1;
    }

    char file_contents[MAX_INPUT_SIZE];
    memset(file_contents, 0, sizeof(file_contents));

    size_t bytes_read = fread(file_contents, 1, sizeof(file_contents) - 1, fp);
    fclose(fp);

    if (bytes_read == 0) {
        return 1;
    }

    /* Process the data */
    process_user_profile(file_contents);

    return 0;
}
