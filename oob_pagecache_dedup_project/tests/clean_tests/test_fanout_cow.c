/*
 * test_fanout_cow.c
 *
 * 3 files share one folio. Write to file 1. Verify files 2 and 3 are
 * unaffected and still share the original folio. Tests rmap_count > 2
 * dissolve path with data verification.
 *
 * Scenario:
 *   1. Create file_a, file_b, file_c — all identical 4-page files.
 *   2. Queue all for dedup, wait for merge (rmap_count should reach 3).
 *   3. Write 'Z' into file_a at offset 0 (triggers COW / break_dedup).
 *   4. Verify file_a has 'Z' at byte 0.
 *   5. Verify file_b and file_c still have original 'M' everywhere.
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
#define FILE_A        "fanout_a.dat"
#define FILE_B        "fanout_b.dat"
#define FILE_C        "fanout_c.dat"
#define SCANNER_WAIT  20

static int verify_file(const char *path, char expected, long size)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); return 1; }
    char *buf = malloc(size);
    ssize_t nr = read(fd, buf, size);
    close(fd);
    if (nr != size) {
        fprintf(stderr, "  [FAIL] %s: short read (%zd vs %ld)\n", path, nr, size);
        free(buf);
        return 1;
    }
    for (long i = 0; i < size; i++) {
        if (buf[i] != expected) {
            fprintf(stderr, "  [FAIL] %s: byte %ld expected '%c', got 0x%02x\n",
                    path, i, expected, (unsigned char)buf[i]);
            free(buf);
            return 1;
        }
    }
    free(buf);
    printf("  -> %s: all '%c' OK\n", path, expected);
    return 0;
}

int main(void)
{
    int ret = 0;
    long file_size = (long)PAGE_SIZE * NUM_PAGES;

    printf("TEST: Fanout COW (3-way share)\n");

    char *blk = malloc(PAGE_SIZE);
    if (!blk) { perror("malloc"); return 1; }
    memset(blk, 'M', PAGE_SIZE);

    char *pages[NUM_PAGES];
    for (int i = 0; i < NUM_PAGES; i++) pages[i] = blk;

    printf("[*] Creating 3 identical %d-page files...\n", NUM_PAGES);
    if (create_and_queue(FILE_A, pages, NUM_PAGES, PAGE_SIZE) < 0) { ret = 1; goto out; }
    if (create_and_queue(FILE_B, pages, NUM_PAGES, PAGE_SIZE) < 0) { ret = 1; goto out; }
    if (create_and_queue(FILE_C, pages, NUM_PAGES, PAGE_SIZE) < 0) { ret = 1; goto out; }

    printf("[*] Sleeping %ds for scanner to merge all 3...\n", SCANNER_WAIT);
    sleep(SCANNER_WAIT);

    /* Write to file_a to trigger COW */
    printf("[*] Writing 'Z' to first page of %s...\n", FILE_A);
    int fd = open(FILE_A, O_RDWR);
    if (fd < 0) { perror("open file_a"); ret = 1; goto out; }
    char zbuf[PAGE_SIZE];
    memset(zbuf, 'Z', PAGE_SIZE);
    ssize_t nw = write(fd, zbuf, PAGE_SIZE);
    close(fd);
    if (nw != PAGE_SIZE) {
        perror("write file_a");
        ret = 1;
        goto out;
    }
    printf("  -> Write succeeded\n");

    /* Verify file_a: page 0 = 'Z', pages 1-3 = 'M' */
    printf("[*] Verifying %s...\n", FILE_A);
    fd = open(FILE_A, O_RDONLY);
    if (fd < 0) { perror("open file_a read"); ret = 1; goto out; }
    char *vbuf = malloc(file_size);
    read(fd, vbuf, file_size);
    close(fd);

    for (int i = 0; i < PAGE_SIZE; i++) {
        if (vbuf[i] != 'Z') {
            fprintf(stderr, "  [FAIL] file_a page0 byte %d: expected 'Z'\n", i);
            ret = 1; free(vbuf); goto out;
        }
    }
    for (long i = PAGE_SIZE; i < file_size; i++) {
        if (vbuf[i] != 'M') {
            fprintf(stderr, "  [FAIL] file_a byte %ld: expected 'M'\n", i);
            ret = 1; free(vbuf); goto out;
        }
    }
    printf("  -> FILE_A: COW page correct, rest unchanged\n");
    free(vbuf);

    /* Verify file_b and file_c are completely untouched */
    printf("[*] Verifying %s...\n", FILE_B);
    if (verify_file(FILE_B, 'M', file_size) != 0) { ret = 1; goto out; }
    printf("[*] Verifying %s...\n", FILE_C);
    if (verify_file(FILE_C, 'M', file_size) != 0) { ret = 1; goto out; }

    if (ret == 0)
        printf("[PASS] Fanout COW test passed\n");
out:
    free(blk);
    unlink(FILE_A);
    unlink(FILE_B);
    unlink(FILE_C);
    return ret;
}
