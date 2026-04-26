#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include "common.h"

int main() {
    long page_size = 4096;

    mkdir("folder_alpha", 0755);
    mkdir("folder_beta", 0755);
    mkdir("folder_gamma", 0755);

    char *blk_Z = malloc(page_size); memset(blk_Z, 'Z', page_size);

    printf("TEST 3: Multi-File Multi-Folder Dedup\n");

    char *pages[] = {blk_Z};

    create_and_queue("folder_alpha/test3_file1.txt", pages, 1, page_size);
    create_and_queue("folder_beta/test3_file2.txt", pages, 1, page_size);
    create_and_queue("folder_gamma/test3_file3.txt", pages, 1, page_size);

    free(blk_Z);
    return 0;
}