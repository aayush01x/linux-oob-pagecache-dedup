#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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

    sleep(2); 

    printf("Verifying cross-folder file contents...\n");
    
    char *read_buf = malloc(page_size);
    int all_passed = 1;

    // Array of files to loop through for clean verification
    const char *files[] = {
        "folder_alpha/test3_file1.txt",
        "folder_beta/test3_file2.txt",
        "folder_gamma/test3_file3.txt"
    };

    for (int i = 0; i < 3; i++) {
        FILE *f = fopen(files[i], "rb");
        if (!f) {
            printf("ERROR: Failed to open %s for verification.\n", files[i]);
            all_passed = 0;
            continue;
        }

        size_t bytes_read = fread(read_buf, 1, page_size, f);
        if (bytes_read != page_size) {
            printf("ERROR: Could not read full page from %s.\n", files[i]);
            all_passed = 0;
        } else if (memcmp(read_buf, blk_Z, page_size) != 0) {
            printf("DATA CORRUPTION: %s does not match expected data 'Z'!\n", files[i]);
            all_passed = 0;
        } else {
            printf("  Verified: %s (Data intact)\n", files[i]);
        }

        fclose(f);
    }

    free(read_buf);

    if (all_passed) {
        printf("SUCCESS: All 3 files across different folders share the same physical page, and data is perfectly intact!\n");
    } else {
        printf("TEST FAILED: The kernel module corrupted the page cache during cross-folder dedup.\n");
    }

    free(blk_Z);
    return 0;
}



