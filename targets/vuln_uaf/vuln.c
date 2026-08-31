/*
 * vuln_uaf/vuln.c
 * Deliberately vulnerable: CWE-416 Use-After-Free
 * Used for test case D2 / P2
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int id;
    char name[32];
} Item;

Item *create_item(int id, const char *name) {
    Item *it = (Item *)malloc(sizeof(Item));
    if (!it) return NULL;
    it->id = id;
    strncpy(it->name, name, sizeof(it->name) - 1);
    it->name[sizeof(it->name) - 1] = '\0';
    return it;
}

void delete_item(Item *it) {
    free(it);  /* item is freed here */
}

/* VULN: accesses it->name after free — CWE-416 */
void print_item_after_delete(Item *it) {
    delete_item(it);
    printf("Item ID: %d, Name: %s\n", it->id, it->name);  /* CWE-416: heap-use-after-free */
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    char buf[32] = {0};
    fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);

    Item *item = create_item(1, buf);
    if (!item) return 1;
    print_item_after_delete(item);
    return 0;
}
