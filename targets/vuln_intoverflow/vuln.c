/*
 * vuln_intoverflow/vuln.c
 * Deliberately vulnerable: CWE-190 Integer Overflow leading to heap OOB write
 * Used for test case D3
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* VULN: element_count * element_size can overflow uint32_t */
void *safe_alloc(uint32_t element_count, uint32_t element_size) {
    uint32_t total = element_count * element_size;  /* CWE-190: integer overflow */
    if (total == 0) return NULL;
    return malloc(total);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;

    uint32_t count = 0, size = 0;
    fread(&count, sizeof(uint32_t), 1, f);
    fread(&size, sizeof(uint32_t), 1, f);
    fclose(f);

    char *buf = (char *)safe_alloc(count, size);
    if (!buf) {
        fprintf(stderr, "Allocation failed or overflow detected\n");
        return 1;
    }
    /* Write count*size bytes — but buf may be too small due to overflow */
    memset(buf, 'A', (size_t)count * size);  /* heap OOB write */
    printf("Allocated and wrote %u * %u bytes\n", count, size);
    free(buf);
    return 0;
}
