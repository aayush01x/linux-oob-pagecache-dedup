#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "common.h"

int main() {
    long page_size = 4096;

    char *blk_A = malloc(page_size); memset(blk_A, 'A', page_size);
    char *blk_B = malloc(page_size); memset(blk_B, 'B', page_size);
    char *blk_X = malloc(page_size); memset(blk_X, 'X', page_size);

    printf("TEST 1: Cross-File Same Folder\n");

    char *f1[] = {blk_A, blk_X};
    char *f2[] = {blk_X, blk_B};

    create_and_queue("test1_file1.txt", f1, 2, page_size);
    create_and_queue("test1_file2.txt", f2, 2, page_size);

    free(blk_A); free(blk_B); free(blk_X);
    return 0;
}