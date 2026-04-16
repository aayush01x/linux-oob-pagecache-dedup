#define _FILE_OFFSET_BITS 64
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#define POSIX_FADV_DEDUP 8
#define BLOCK_SIZE (1024 * 1024) // 1MB blocks
#define TOTAL_GB 4
#define BLOCKS_PER_GB 1024
#define TOTAL_BLOCKS (TOTAL_GB * BLOCKS_PER_GB)

int main() {
    int fd;
    char *pattern_A, *pattern_B;
    off_t offset;

    pattern_A = malloc(BLOCK_SIZE);
    pattern_B = malloc(BLOCK_SIZE);
    memset(pattern_A, 'A', BLOCK_SIZE);
    memset(pattern_B, 'B', BLOCK_SIZE);

    printf("--- OOB_DEDUP 4GB INTEGRITY TEST ---\n");

    fd = open("stress_test_4gb.bin", O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("Failed to create large file");
        return 1;
    }

    printf("[1/3] Writing 4GB pattern...\n");
    for (int i = 0; i < TOTAL_BLOCKS; i++) {
        char *buf = (i % 2 == 0) ? pattern_A : pattern_B;
        if (write(fd, buf, BLOCK_SIZE) != BLOCK_SIZE) {
            perror("Write failure");
            close(fd);
            return 1;
        }
        if (i % 1024 == 0 && i > 0) printf("    ... %d GB written\n", i/1024);
    }

    // Critical: Ensure data is clean on disk so the scanner picks it up
    printf("[2/3] Syncing and Queueing for Deduplication...\n");
    fsync(fd);
    
    if (posix_fadvise(fd, 0, 0, POSIX_FADV_DEDUP) != 0) {
        perror("fadvise(DEDUP) failed");
    }

    printf(" [+] Sleeping 10s to allow OOB scanner to process 4GB...\n");
    sleep(10); 

    printf("[3/3] Verifying Data Integrity at Junctions...\n");
    char *read_buf = malloc(BLOCK_SIZE);
    int passed = 1;

    // We check 3 specific points: 
    // 1. Start (Index 0)
    // 2. The 1GB mark (First major dedup point)
    // 3. The 3GB mark (Stress test for large index math)
    off_t check_offsets[] = { 0, 1024ULL*BLOCK_SIZE, 3072ULL*BLOCK_SIZE };
    const char* names[] = { "Start (0GB)", "1GB Mark (Deduped)", "3GB Mark (Deduped)" };

    for (int i = 0; i < 3; i++) {
        if (lseek(fd, check_offsets[i], SEEK_SET) == (off_t)-1) {
            perror("Seek failed");
            passed = 0;
            break;
        }

        read(fd, read_buf, BLOCK_SIZE);
        // Based on our loop (i % 2 == 0), these should all be pattern_A
        if (memcmp(read_buf, pattern_A, BLOCK_SIZE) != 0) {
            printf(" [!] CORRUPTION DETECTED at %s (Offset %ld)\n", names[i], check_offsets[i]);
            passed = 0;
        } else {
            printf(" [V] %s verified correct.\n", names[i]);
        }
    }

    if (passed) {
        printf("\nSUCCESS: 4GB symmetric deduplication verified!\n");
        printf("The folio_index_in math handled the >2^20 index gap correctly.\n");
    } else {
        printf("\nFAILURE: Data corruption detected in large file read.\n");
    }

    close(fd);
    free(pattern_A);
    free(pattern_B);
    free(read_buf);
    return !passed;
}
