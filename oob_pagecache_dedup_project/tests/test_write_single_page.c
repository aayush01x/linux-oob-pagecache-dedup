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

    printf("TEST: Phase 1 - Page Cache Copy-On-Write (Expecting Success)\n");

    char *pages[] = {blk_a};

    // 1. Create identical files
    printf("[*] Creating identical files to trigger dedup...\n");
    create_and_queue("file_trap_1.txt", pages, 1, page_size);
    create_and_queue("file_trap_2.txt", pages, 1, page_size);

    // 2. Wait for OOB thread
    printf("[*] Sleeping 5s for background merge...\n");
    sleep(5); 

    printf("[*] Background merge should be complete. Check dmesg for dedup success.\n");
    printf("[*] Press Enter to attempt writing to file 1...\n");
    getchar();

    // 3. The Trigger: Attempt a partial write to file 1
    // We open as O_RDWR so we can seek and verify later.
    printf("[*] Attempting to overwrite the middle of file_trap_1.txt...\n");
    int fd1 = open("file_trap_1.txt", O_RDWR);
    if (fd1 < 0) {
        perror("open failed on file_trap_1");
        return 1;
    }
    
    // Seek to offset 1024 and write 256 bytes of 'B's
    lseek(fd1, 1024, SEEK_SET);
    ssize_t bytes_written = write(fd1, blk_b, 256);
    
    if (bytes_written < 0) {
        perror("    -> FAILED: Write was rejected! (Did you leave the EBUSY return code in the kernel?)");
        close(fd1);
        return 1;
    } else {
        printf("    -> SUCCESS: Write went through! (%zd bytes written)\n", bytes_written);
    }
    
    // 4. Data Verification
    printf("\n[*] Verifying data integrity in both files...\n");
    char *verify_buf = malloc(page_size);

    // Verify File 1 (Should be AAAA...BBBB...AAAA)
    lseek(fd1, 0, SEEK_SET);
    read(fd1, verify_buf, page_size);
    
    if (verify_buf[0] == 'A' && verify_buf[1024] == 'B' && verify_buf[1279] == 'B' && verify_buf[1280] == 'A') {
        printf("    -> FILE 1: Data perfectly intact! (Read-Modify-Write and folio_copy succeeded)\n");
    } else {
        printf("    -> FILE 1: CORRUPTION DETECTED! The kernel folio copy failed, or data was wiped.\n");
    }
    close(fd1);

    // Verify File 2 (Should remain ALL A's)
    int fd2 = open("file_trap_2.txt", O_RDONLY);
    read(fd2, verify_buf, page_size);
    
    if (verify_buf[0] == 'A' && verify_buf[1024] == 'A' && verify_buf[1280] == 'A') {
        printf("    -> FILE 2: Unchanged! (Dedup isolation worked perfectly!)\n");
    } else {
        printf("    -> FILE 2: CORRUPTION DETECTED! File 2 was modified by File 1's write! (Page replacement failed)\n");
    }
    close(fd2);

    printf("\n[*] Press Enter to clean up...\n");
    getchar();

    // 5. Cleanup
    printf("[*] Cleaning up...\n");
    remove("file_trap_1.txt");
    printf("removed 1file\n");
    remove("file_trap_2.txt");

    free(blk_a);
    free(blk_b);
    free(verify_buf);

    printf("TEST FINISHED: Check dmesg to confirm your kernel swap logic printed.\n");
    return 0;
}
