/*
 * test_truncate_deduped.c
 *
 * Truncate a deduped file, then verify the other file still reads correctly.
 * Directly exercises truncate_inode_pages_range + oob_dedup_disconnect_folio.
 *
 * Scenario:
 *   1. Create file_a (4 pages of 'X') and file_b (4 pages of 'X') — identical.
 *   2. Queue both for dedup, wait for merge.
 *   3. ftruncate file_a to 0 bytes.
 *   4. Read file_b and verify all data is intact ('X').
 *   5. Also: ftruncate file_b to half size, then verify partial content.
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
#define FILE_A        "trunc_dedup_a.dat"
#define FILE_B        "trunc_dedup_b.dat"
#define SCANNER_WAIT  20

int main(void)
{
    int ret = 0;
    long file_size = (long)PAGE_SIZE * NUM_PAGES;

    printf("TEST: Truncate Deduped File\n");

    /* --- 1. Create identical files ------------------------------------ */
    char *blk = malloc(PAGE_SIZE);
    if (!blk) { perror("malloc"); return 1; }
    memset(blk, 'X', PAGE_SIZE);

    char *pages[NUM_PAGES];
    for (int i = 0; i < NUM_PAGES; i++)
        pages[i] = blk;

    printf("[*] Creating two identical %d-page files...\n", NUM_PAGES);
    if (create_and_queue(FILE_A, pages, NUM_PAGES, PAGE_SIZE) < 0) { ret = 1; goto out; }
    if (create_and_queue(FILE_B, pages, NUM_PAGES, PAGE_SIZE) < 0) { ret = 1; goto out; }

    /* --- 2. Wait for dedup -------------------------------------------- */
    printf("[*] Sleeping %ds for background merge...\n", SCANNER_WAIT);
    sleep(SCANNER_WAIT);

    /* --- 3. Truncate file_a to 0 bytes -------------------------------- */
    printf("[*] Truncating %s to 0 bytes...\n", FILE_A);
    int fd_a = open(FILE_A, O_RDWR);
    if (fd_a < 0) { perror("open file_a"); ret = 1; goto out; }

    if (ftruncate(fd_a, 0) < 0) {
        perror("ftruncate file_a to 0");
        close(fd_a);
        ret = 1;
        goto out;
    }
    close(fd_a);
    printf("  -> Truncated OK\n");

    /* --- 4. Verify file_b is completely intact ------------------------ */
    printf("[*] Reading back %s to verify integrity...\n", FILE_B);
    int fd_b = open(FILE_B, O_RDONLY);
    if (fd_b < 0) { perror("open file_b"); ret = 1; goto out; }

    char *vbuf = malloc(file_size);
    if (!vbuf) { perror("malloc vbuf"); close(fd_b); ret = 1; goto out; }

    ssize_t nr = read(fd_b, vbuf, file_size);
    if (nr != file_size) {
        fprintf(stderr, "  [FAIL] Short read on file_b: expected %ld, got %zd\n",
                file_size, nr);
        close(fd_b);
        ret = 1;
        goto out_vbuf;
    }
    close(fd_b);

    for (long i = 0; i < file_size; i++) {
        if (vbuf[i] != 'X') {
            fprintf(stderr, "  [FAIL] file_b byte %ld: expected 'X', got 0x%02x\n",
                    i, (unsigned char)vbuf[i]);
            ret = 1;
            goto out_vbuf;
        }
    }
    printf("  -> FILE_B: All %ld bytes intact after FILE_A truncation\n", file_size);

    /* --- 5. Now truncate file_b to half, verify remaining half -------- */
    long half = file_size / 2;
    printf("[*] Truncating %s to %ld bytes (half)...\n", FILE_B, half);
    fd_b = open(FILE_B, O_RDWR);
    if (fd_b < 0) { perror("open file_b rw"); ret = 1; goto out_vbuf; }

    if (ftruncate(fd_b, half) < 0) {
        perror("ftruncate file_b to half");
        close(fd_b);
        ret = 1;
        goto out_vbuf;
    }

    lseek(fd_b, 0, SEEK_SET);
    memset(vbuf, 0, file_size);
    nr = read(fd_b, vbuf, half);
    close(fd_b);

    if (nr != half) {
        fprintf(stderr, "  [FAIL] Short read after half-truncate: expected %ld, got %zd\n",
                half, nr);
        ret = 1;
        goto out_vbuf;
    }

    for (long i = 0; i < half; i++) {
        if (vbuf[i] != 'X') {
            fprintf(stderr, "  [FAIL] file_b (half) byte %ld: expected 'X', got 0x%02x\n",
                    i, (unsigned char)vbuf[i]);
            ret = 1;
            goto out_vbuf;
        }
    }
    printf("  -> FILE_B: Remaining %ld bytes intact after half truncation\n", half);

    if (ret == 0)
        printf("[PASS] Truncate deduped test passed\n");

out_vbuf:
    free(vbuf);
out:
    free(blk);
    unlink(FILE_A);
    unlink(FILE_B);
    return ret;
}
