/*
 * multi_bug/multi.c
 * Two distinct bugs: CWE-787 (BOF) + CWE-416 (UAF)
 * Used for dedup testing (test case D5)
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Bug 1: CWE-787 stack BOF */
void bug1_bof(const char *input) {
    char small[16];
    strcpy(small, input);  /* overflow if input > 15 chars */
}

/* Bug 2: CWE-416 use-after-free */
void bug2_uaf(void) {
    char *p = (char *)malloc(32);
    if (!p) return;
    strcpy(p, "hello");
    free(p);
    printf("%s\n", p);  /* use-after-free */
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    char buf[4096] = {0};
    fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);

    if (buf[0] == 'U') {
        bug2_uaf();
    } else {
        bug1_bof(buf);
    }
    return 0;
}
