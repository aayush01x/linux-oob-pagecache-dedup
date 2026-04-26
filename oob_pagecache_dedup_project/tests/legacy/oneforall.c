#define _FILE_OFFSET_BITS 64
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#define POSIX_FADV_DEDUP 8
#define PAGE_SIZE 4096

void print_usage(char *prog) {
    printf("Usage: %s <filename> <size_mb> <pattern_char> <wait_seconds>\n", prog);
    printf("Example: %s test_4gb.bin 4096 A 15\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        print_usage(argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    long size_mb = atol(argv[2]);
    char pattern = argv[3][0];
    int wait_sec = atoi(argv[4]);
    
    long total_pages = (size_mb * 1024 * 1024) / PAGE_SIZE;
    char *buf = malloc(PAGE_SIZE);
    memset(buf, pattern, PAGE_SIZE);

    printf("[*] Target: %s | Size: %ld MB (%ld pages) | Pattern: '%c'\n", 
            filename, size_mb, total_pages, pattern);

    // 1. Create and Write File
    int fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("Open failed"); return 1; }

    printf("[1/4] Writing data...");
    for (long i = 0; i < total_pages; i++) {
        if (write(fd, buf, PAGE_SIZE) != PAGE_SIZE) {
            perror("\nWrite failed");
            return 1;
        }
        if (i % 25600 == 0) printf("."); // Progress dot every ~100MB
    }
    printf(" Done.\n");

    // 2. Sync to make pages CLEAN (Mandatory for OOB scanner)
    printf("[2/4] Syncing to disk and flagging for OOB_DEDUP...\n");
    fsync(fd);
    if (posix_fadvise(fd, 0, 0, POSIX_FADV_DEDUP) != 0) {
        perror("fadvise DEDUP failed");
    }

    // 3. Load into Page Cache (The Read Trigger)
    printf("[3/4] Warming up Page Cache...");
    lseek(fd, 0, SEEK_SET);
    for (long i = 0; i < total_pages; i++) {
        if (read(fd, buf, PAGE_SIZE) != PAGE_SIZE) {
            perror("\nRead trigger failed");
            return 1;
        }
    }
    printf(" Cache loaded.\n");

    // 4. Wait for Scanner
    printf("[*] Sleeping for %d seconds to allow scanner to process...\n", wait_sec);
    sleep(wait_sec);

    // 5. Verification Step
    printf("[4/4] Verifying data integrity via VFS read path...");
    lseek(fd, 0, SEEK_SET);
    int corrupted = 0;
    for (long i = 0; i < total_pages; i++) {
        if (read(fd, buf, PAGE_SIZE) != PAGE_SIZE) {
            printf("\n[!] Read error at page %ld\n", i);
            corrupted = 1;
            break;
        }
        if (buf[0] != pattern) { // Simple check first byte
            printf("\n[!] DATA CORRUPTION at page %ld! Expected '%c', got '%c'\n", 
                    i, pattern, buf[0]);
            corrupted = 1;
            break;
        }
    }

    if (!corrupted) {
        printf(" SUCCESS! Data is intact.\n");
    }

    close(fd);
    free(buf);
    return corrupted;
}
