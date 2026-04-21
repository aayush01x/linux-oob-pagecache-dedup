#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "common.h"

int main() {
    long page_size = 4096;
    
    // Original data block ('A's)
    char *blk_a = malloc(page_size);
    memset(blk_a, 'A', page_size); 
    
    // New data block to attempt to write ('B's)
    char *blk_b = malloc(page_size);
    memset(blk_b, 'B', page_size);

    printf("TEST: Phase 1 - The CoW Trap (Expecting EBUSY rejection)\n");

    char *pages[] = {blk_a};

    // 1. Create identical files
    printf("[*] Creating identical files to trigger dedup...\n");
    create_and_queue("file_trap_1.txt", pages, 1, page_size);
    create_and_queue("file_trap_2.txt", pages, 1, page_size);

    // 2. Wait for OOB thread
    printf("[*] Sleeping 5s for background merge...\n");
    sleep(5); 

    printf("[*] Background merge should be complete. Check dmesg for dedup success.\n");
    printf("[*] Press Enter to attempt writing to file 1 (Should be rejected)...\n");
    getchar();

    // 3. The Trap: Attempt to write to file 1
    // If your hook in iomap_write_begin is working, this should fail.
    printf("[*] Attempting to overwrite file_trap_1.txt...\n");
    int fd = open("file_trap_1.txt", O_WRONLY);
    if (fd < 0) {
        perror("open failed on file_trap_1");
        return 1;
    }
    
    ssize_t bytes_written = write(fd, blk_b, page_size);
    
    if (bytes_written < 0) {
        if (errno == EBUSY) {
            printf("    -> SUCCESS: Write was intercepted and cleanly rejected with EBUSY!\n");
        } else {
            perror("    -> FAILED: Write failed, but with an unexpected error");
        }
    } else {
        printf("    -> FAILED: Write succeeded! The trap in iomap_write_begin was missed or didn't return -EBUSY.\n");
    }
    
    close(fd);

    printf("[*] Press Enter to clean up...\n");
    getchar();

    // 4. Cleanup
    printf("[*] Cleaning up...\n");
    remove("file_trap_1.txt");
    remove("file_trap_2.txt");

    free(blk_a);
    free(blk_b);

    printf("TEST FINISHED: Check dmesg to confirm your pr_info trap message printed.\n");
    return 0;
}
