#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include "common.h"

int main() {
    long page_size = 4096;

    mkdir("folder_alpha", 0755);
    mkdir("folder_beta", 0755);

    char *blk_A = malloc(page_size); memset(blk_A, 'A', page_size);
    char *blk_B = malloc(page_size); memset(blk_B, 'B', page_size);
    char *blk_M = malloc(page_size); memset(blk_M, 'M', page_size);

    printf("TEST 2: Cross-File Different Folders\n");

    char *f1[] = {blk_M, blk_A};
    char *f2[] = {blk_B, blk_M};

    create_and_queue("folder_alpha/test2_file1.txt", f1, 2, page_size);
    create_and_queue("folder_beta/test2_file2.txt", f2, 2, page_size);

    free(blk_A); free(blk_B); free(blk_M);
    return 0;
}