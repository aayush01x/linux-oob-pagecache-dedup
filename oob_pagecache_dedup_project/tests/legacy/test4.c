#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "common.h"

int main() {
    long page_size = 4096;

    char *blk_A = malloc(page_size); memset(blk_A, 'A', page_size);
    char *blk_B = malloc(page_size); memset(blk_B, 'B', page_size);

    printf("TEST 4: Reading post Internal File Deduplication \n");

    char *pages[] = {blk_A, blk_B, blk_A};
    create_and_queue("test0_internal.txt", pages, 3, page_size);

    sleep(2); 
    
        printf("Verifying file contents...\n");
        FILE *f = fopen("test0_internal.txt", "rb");
        if (!f) {
            perror("ERROR: Failed to open file for verification");
            free(blk_A); free(blk_B);
            return 1;
        }
    
        char *read_buf = malloc(page_size);
        int passed = 1;
    
        // Verify Index 0 (Expected: A)
        fread(read_buf, 1, page_size, f);
        if (memcmp(read_buf, blk_A, page_size) != 0) {
            printf("DATA CORRUPTION: Index 0 does not match 'A'!\n");
            passed = 0;
        }
    
        // Verify Index 1 (Expected: B)
        fread(read_buf, 1, page_size, f);
        if (memcmp(read_buf, blk_B, page_size) != 0) {
            printf("DATA CORRUPTION: Index 1 does not match 'B'!\n");
            passed = 0;
        }
    
        // Verify Index 2 (Expected: A - This is the merged folio!)
        fread(read_buf, 1, page_size, f);
        if (memcmp(read_buf, blk_A, page_size) != 0) {
            printf("DATA CORRUPTION: Index 2 (Deduplicated Folio) does not match 'A'!\n");
            passed = 0;
        }
    
        fclose(f);
        free(read_buf);
    
        if (passed) {
            printf("SUCCESS: Data integrity verified! VFS successfully read the deduplicated folios.\n");
        } else {
            printf("TEST FAILED: The kernel module corrupted the page cache.\n");
        }

    free(blk_A);
    free(blk_B);

    return 0;
}
