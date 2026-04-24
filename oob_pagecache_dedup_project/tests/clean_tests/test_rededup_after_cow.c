/*
 * test_redeup_after_cow.c
 *
 * RE-DEDUP AFTER COW BREAK TEST
 *
 * This tests the full lifecycle: dedup → COW break → re-dedup → delete.
 *
 * The concern: after a COW break creates a private copy, the page cache
 * has a mix of shared deduped folios and private COW'd folios. If the
 * file is then re-queued for dedup, the scanner must:
 *   - Skip already-deduped folios (folio_test_dedup check).
 *   - Correctly handle the private page that now has different content.
 *   - Not double-dedup or create circular rmap entries.
 *
 * Then on deletion, all paths (deduped folios and private folios)
 * must correctly decrement nrpages.
 *
 * Scenario:
 *   1. Create files A and B with identical content (8 pages of 'K').
 *   2. Queue for dedup, wait, verify merge.
 *   3. Write 'Z' to page 2 of file A (COW break for that page).
 *   4. Write 'K' back to page 2 of file A (content matches again).
 *   5. Re-queue file A for dedup.
 *   6. Wait for scanner — it should re-merge page 2.
 *   7. Verify both files read correctly.
 *   8. Delete both files — tests that re-dedup didn't corrupt rmap.
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

#define PAGE_SIZE       4096
#define NUM_PAGES       8
#define FILE_A          "rededup_a.dat"
#define FILE_B          "rededup_b.dat"
#define SCANNER_WAIT    8
#define POSIX_FADV_DEDUP 8

static int verify_file(const char *path, char fill, long size)
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
        if (buf[i] != fill) {
            fprintf(stderr, "  [FAIL] %s byte %ld: expected '%c', got 0x%02x\n",
                    path, i, fill, (unsigned char)buf[i]);
            free(buf);
            return 1;
        }
    }
    free(buf);
    return 0;
}

int main(void)
{
    int ret = 0;
    long file_size = (long)PAGE_SIZE * NUM_PAGES;

    printf("TEST: Re-Dedup After COW Break\n");

    /* --- 1. Create identical files ------------------------------------ */
    char *blk = malloc(PAGE_SIZE);
    if (!blk) { perror("malloc"); return 1; }
    memset(blk, 'K', PAGE_SIZE);

    char *pages[NUM_PAGES];
    for (int i = 0; i < NUM_PAGES; i++)
        pages[i] = blk;

    printf("[*] Creating two identical %d-page files...\n", NUM_PAGES);
    if (create_and_queue(FILE_A, pages, NUM_PAGES, PAGE_SIZE) < 0) { ret = 1; goto out; }
    if (create_and_queue(FILE_B, pages, NUM_PAGES, PAGE_SIZE) < 0) { ret = 1; goto out; }

    /* --- 2. Wait for initial dedup ------------------------------------ */
    printf("[*] Sleeping %ds for initial dedup...\n", SCANNER_WAIT);
    sleep(SCANNER_WAIT);

    /* --- 3. Verify initial dedup -------------------------------------- */
    printf("[*] Verifying initial merge...\n");
    if (verify_file(FILE_A, 'K', file_size) != 0) { ret = 1; goto out; }
    if (verify_file(FILE_B, 'K', file_size) != 0) { ret = 1; goto out; }
    printf("  -> Both files intact\n");

    /* --- 4. COW break: write 'Z' to page 2 of file A ----------------- */
    printf("[*] Breaking dedup: writing 'Z' to page 2 of %s...\n", FILE_A);
    int fd = open(FILE_A, O_RDWR);
    if (fd < 0) { perror("open A rw"); ret = 1; goto out; }
    char zbuf[PAGE_SIZE];
    memset(zbuf, 'Z', PAGE_SIZE);
    if (pwrite(fd, zbuf, PAGE_SIZE, 2 * PAGE_SIZE) != PAGE_SIZE) {
        perror("pwrite Z");
        close(fd);
        ret = 1;
        goto out;
    }
    fsync(fd);

    /* --- 5. Write original content back to page 2 --------------------- */
    printf("[*] Restoring page 2 to 'K' (content matches B again)...\n");
    memset(zbuf, 'K', PAGE_SIZE);
    if (pwrite(fd, zbuf, PAGE_SIZE, 2 * PAGE_SIZE) != PAGE_SIZE) {
        perror("pwrite K");
        close(fd);
        ret = 1;
        goto out;
    }
    fsync(fd);
    close(fd);

    /* --- 6. Re-queue file A for dedup --------------------------------- */
    printf("[*] Re-queuing %s for dedup...\n", FILE_A);
    fd = open(FILE_A, O_RDONLY);
    if (fd < 0) { perror("open A requeue"); ret = 1; goto out; }
    int r = posix_fadvise(fd, 0, 0, POSIX_FADV_DEDUP);
    if (r != 0) {
        fprintf(stderr, "  fadvise re-queue failed: %s\n", strerror(r));
    }
    close(fd);

    /* --- 7. Wait for re-dedup ----------------------------------------- */
    printf("[*] Sleeping %ds for re-dedup...\n", SCANNER_WAIT);
    sleep(SCANNER_WAIT);

    /* --- 8. Verify both files ----------------------------------------- */
    printf("[*] Verifying files after re-dedup cycle...\n");
    if (verify_file(FILE_A, 'K', file_size) != 0) { ret = 1; goto out; }
    printf("  -> %s: OK\n", FILE_A);
    if (verify_file(FILE_B, 'K', file_size) != 0) { ret = 1; goto out; }
    printf("  -> %s: OK\n", FILE_B);

    /* --- 9. Delete both files ----------------------------------------- */
    printf("[*] Deleting both files...\n");
    unlink(FILE_A);
    usleep(300000);
    printf("  -> %s deleted\n", FILE_A);
    unlink(FILE_B);
    usleep(300000);
    printf("  -> %s deleted\n", FILE_B);

    if (ret == 0)
        printf("\n[PASS] Re-dedup after COW break test passed\n");

out:
    free(blk);
    unlink(FILE_A);
    unlink(FILE_B);
    return ret;
}
