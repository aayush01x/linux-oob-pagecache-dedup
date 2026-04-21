#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include "common.h"

void fill_with_pattern(char *buf, size_t size, const char *pattern) {
    for (size_t i = 0; i < size; i += 8) {
        size_t to_copy = (size - i < 8) ? (size - i) : 8;
        memcpy(buf + i, pattern, to_copy);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: %s <size_kb> <8_byte_pattern1> <8_byte_pattern2>\n", argv[0]);
        printf("Example: %s 4096 DEADBEAF CAFEBABE\n", argv[0]);
        return 1;
    }

    long file_size = atol(argv[1]) * 1024;
    char *pat1 = argv[2];
    char *pat2 = argv[3];

    if (strlen(pat1) != 8 || strlen(pat2) != 8) {
        printf("Error: Patterns must be exactly 8 bytes!\n");
        return 1;
    }

    // Allocate buffers
    char *blk_orig = malloc(file_size);
    char *blk_mod = malloc(8); // We only write 8 bytes to trigger CoW
    fill_with_pattern(blk_orig, file_size, pat1);
    memcpy(blk_mod, pat2, 8);

    printf("TEST: OOB Dedup Stress (Size: %ld KB, P1: %s, P2: %s)\n", atol(argv[1]), pat1, pat2);

    // 1. Create identical files
    // Note: Assuming create_and_queue handles the buffer. 
    // If it expects an array of pages, you'll need to wrap blk_orig.
    printf("[*] Creating 2 identical files of size %ld bytes...\n", file_size);
    create_and_queue("file_trap_1.txt", &blk_orig, 1, file_size);
    create_and_queue("file_trap_2.txt", &blk_orig, 1, file_size);

    // 2. Wait for background merge
    printf("[*] Sleeping 5s for background kernel merge...\n");
    sleep(5); 

    printf("[*] Merge should be active. Check 'dmesg | grep OOB_DEDUP'.\n");
    printf("[*] Press Enter to break dedup on File 1 via write...\n");
    getchar();

    // 3. Trigger CoW: Write Pattern 2 to the middle of File 1
    int fd1 = open("file_trap_1.txt", O_RDWR);
    if (fd1 < 0) { perror("open failed"); return 1; }

    off_t target_offset = file_size / 2;
    printf("[*] Writing %s to File 1 at offset %ld...\n", pat2, target_offset);
    lseek(fd1, target_offset, SEEK_SET);
    if (write(fd1, blk_mod, 8) < 0) {
        perror("-> Write FAILED (Kernel likely deadlocked or EBUSY)");
        close(fd1);
        return 1;
    }
    printf(" -> Write SUCCESS.\n");

    // 4. Verification
    printf("\n[*] Verifying Data Integrity...\n");
    char *verify_buf = malloc(file_size);

    // Check File 1: Should have Pat2 at the offset, Pat1 elsewhere
    lseek(fd1, 0, SEEK_SET);
    read(fd1, verify_buf, file_size);
    
    if (memcmp(verify_buf + target_offset, pat2, 8) == 0 && 
        memcmp(verify_buf, pat1, 8) == 0) {
        printf(" -> FILE 1: Verified. Private CoW folio is correct.\n");
    } else {
        printf(" -> FILE 1: CORRUPTION! Data mismatch at offset %ld.\n", target_offset);
    }
    close(fd1);

    // Check File 2: Should be PURE Pattern 1
    int fd2 = open("file_trap_2.txt", O_RDONLY);
    read(fd2, verify_buf, file_size);
    if (memcmp(verify_buf + target_offset, pat1, 8) == 0) {
        printf(" -> FILE 2: Verified. Isolation maintained (Hub dissolved/updated correctly).\n");
    } else {
        printf(" -> FILE 2: CORRUPTION! Write leaked from File 1 into File 2!\n");
    }
    close(fd2);

    printf("\n[*] Test Complete. Check dmesg for 'Hub dissolved' logs.\n");
    printf("[*] Press Enter to cleanup and exit...\n");
    getchar();

    remove("file_trap_1.txt");
    remove("file_trap_2.txt");
    free(blk_orig);
    free(blk_mod);
    free(verify_buf);

    return 0;
}
