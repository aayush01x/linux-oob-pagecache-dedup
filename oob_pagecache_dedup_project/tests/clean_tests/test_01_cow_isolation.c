/*
 * test_01_cow_isolation.c
 *
 * Fully automated COW isolation test (no getchar()).
 * Creates two identical files, waits for the OOB scanner to merge them,
 * writes to file 1, then verifies:
 *   - File 1 has the new data at the written offset and original data elsewhere
 *   - File 2 is completely untouched (dedup isolation)
 *
 * Exit: 0 = PASS, 1 = FAIL
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "common.h"

#define PAGE_SIZE     4096
#define NUM_PAGES     4
#define FILE1         "cow_iso_file1.dat"
#define FILE2         "cow_iso_file2.dat"
#define SCANNER_WAIT  5   /* seconds for the background scanner */

int main(void)
{
    int ret = 0;
    long file_size = (long)PAGE_SIZE * NUM_PAGES;

    printf("TEST: COW Isolation (Automated)\n");

    /* --- 1. Create identical files ------------------------------------ */
    char *blk = malloc(PAGE_SIZE);
    if (!blk) { perror("malloc"); return 1; }
    memset(blk, 'A', PAGE_SIZE);

    char *pages[NUM_PAGES];
    for (int i = 0; i < NUM_PAGES; i++)
        pages[i] = blk;

    printf("[*] Creating two identical %d-page files...\n", NUM_PAGES);
    if (create_and_queue(FILE1, pages, NUM_PAGES, PAGE_SIZE) < 0) { ret = 1; goto out; }
    if (create_and_queue(FILE2, pages, NUM_PAGES, PAGE_SIZE) < 0) { ret = 1; goto out; }

    /* --- 2. Wait for dedup -------------------------------------------- */
    printf("[*] Sleeping %ds for background merge...\n", SCANNER_WAIT);
    sleep(SCANNER_WAIT);

    /* --- 3. Write to file 1 ------------------------------------------ */
    printf("[*] Writing 256 bytes of 'B' at offset 1024 in %s...\n", FILE1);
    int fd1 = open(FILE1, O_RDWR);
    if (fd1 < 0) { perror("open file1"); ret = 1; goto out; }

    char patch[256];
    memset(patch, 'B', sizeof(patch));

    if (lseek(fd1, 1024, SEEK_SET) < 0)  { perror("lseek"); close(fd1); ret = 1; goto out; }
    ssize_t nw = write(fd1, patch, sizeof(patch));
    if (nw < 0) {
        perror("write to file1 failed");
        close(fd1);
        ret = 1;
        goto out;
    }
    printf("  -> Write succeeded (%zd bytes)\n", nw);

    /* --- 4. Verify file 1 -------------------------------------------- */
    printf("[*] Verifying %s...\n", FILE1);
    char *vbuf = malloc(file_size);
    if (!vbuf) { perror("malloc vbuf"); close(fd1); ret = 1; goto out; }

    lseek(fd1, 0, SEEK_SET);
    if (read(fd1, vbuf, file_size) != file_size) {
        perror("read file1");
        ret = 1;
        goto out_vbuf;
    }
    close(fd1);
    fd1 = -1;

    /* bytes [0..1023] should be 'A' */
    for (int i = 0; i < 1024; i++) {
        if (vbuf[i] != 'A') {
            fprintf(stderr, "  [FAIL] FILE1: byte %d expected 'A', got 0x%02x\n", i, (unsigned char)vbuf[i]);
            ret = 1;
            goto out_vbuf;
        }
    }
    /* bytes [1024..1279] should be 'B' */
    for (int i = 1024; i < 1280; i++) {
        if (vbuf[i] != 'B') {
            fprintf(stderr, "  [FAIL] FILE1: byte %d expected 'B', got 0x%02x\n", i, (unsigned char)vbuf[i]);
            ret = 1;
            goto out_vbuf;
        }
    }
    /* bytes [1280..end] should be 'A' */
    for (long i = 1280; i < file_size; i++) {
        if (vbuf[i] != 'A') {
            fprintf(stderr, "  [FAIL] FILE1: byte %ld expected 'A', got 0x%02x\n", i, (unsigned char)vbuf[i]);
            ret = 1;
            goto out_vbuf;
        }
    }
    printf("  -> FILE1: Data correct (CoW private copy OK)\n");

    /* --- 5. Verify file 2 -------------------------------------------- */
    printf("[*] Verifying %s...\n", FILE2);
    int fd2 = open(FILE2, O_RDONLY);
    if (fd2 < 0) { perror("open file2"); ret = 1; goto out_vbuf; }

    if (read(fd2, vbuf, file_size) != file_size) {
        perror("read file2");
        close(fd2);
        ret = 1;
        goto out_vbuf;
    }
    close(fd2);

    for (long i = 0; i < file_size; i++) {
        if (vbuf[i] != 'A') {
            fprintf(stderr, "  [FAIL] FILE2: byte %ld expected 'A', got 0x%02x\n", i, (unsigned char)vbuf[i]);
            fprintf(stderr, "  [FAIL] Write leaked from FILE1 to FILE2!\n");
            ret = 1;
            goto out_vbuf;
        }
    }
    printf("  -> FILE2: Unchanged (dedup isolation maintained)\n");

    if (ret == 0)
        printf("[PASS] COW Isolation test passed\n");

out_vbuf:
    free(vbuf);
out:
    if (fd1 >= 0) close(fd1);
    free(blk);
    unlink(FILE1);
    unlink(FILE2);
    return ret;
}
