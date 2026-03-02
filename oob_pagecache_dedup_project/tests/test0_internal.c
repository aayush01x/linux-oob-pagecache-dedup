#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "common.h"

int main() {
    long page_size = 4096;

    char *blk_A = malloc(page_size); memset(blk_A, 'A', page_size);
    char *blk_B = malloc(page_size); memset(blk_B, 'B', page_size);

    printf("TEST 0: Internal File Deduplication\n");

    char *pages[] = {blk_A, blk_B, blk_A};
    create_and_queue("test0_internal.txt", pages, 3, page_size);

    free(blk_A);
    free(blk_B);

    return 0;
}