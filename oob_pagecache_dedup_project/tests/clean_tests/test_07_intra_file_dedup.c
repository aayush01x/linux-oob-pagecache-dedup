/*
 * test_07_intra_file_dedup.c
 *
 * INTRA-FILE DEDUPLICATION CORRECTNESS TEST
 *
 * This is the hardest scenario for the OOB dedup subsystem: a single file
 * whose pages contain duplicate content at DIFFERENT offsets within the
 * SAME address_space.  This stresses:
 *
 *   - folio_index_in() returning the right index when the same folio
 *     appears at multiple XArray slots in the same mapping.
 *   - filemap_remove_folio_at() clearing the correct slot (not the first
 *     one folio_index_in finds).
 *   - oob_dedup_disconnect_folio() matching on BOTH mapping AND index
 *     (not just mapping) when removing rmap entries.
 *   - truncate_inode_pages_range() batch path skipping
 *     delete_from_page_cache_batch for deduped batches.
 *   - The intra-file dissolve path in disconnect_folio clearing the
 *     remaining XArray slot when last rmap entry shares the same mapping.
 *   - nrpages accounting: each XArray slot contributes nrpages at insert,
 *     so removal must subtract once per slot; clear_inode() BUG_ON(nrpages).
 *
 * Scenario:
 *   1. Create a 16-page file where all pages are identical ('D').
 *      This means all 16 XArray slots contain the same content.
 *   2. Queue for dedup, wait for scanner to merge intra-file duplicates.
 *   3. Verify read-back: all 16 pages should still read 'D'.
 *   4. Write different data to page 0 — triggers COW / break_dedup
 *      for that one slot while 15 others remain shared.
 *   5. Verify page 0 has new data, pages 1-15 still 'D'.
 *   6. Truncate the file to 8 pages — removes 8 shared slots.
 *   7. Verify the remaining 8 pages read correctly.
 *   8. Truncate to 0 — removes all remaining slots.
 *   9. Delete the file. If nrpages != 0 at clear_inode(), kernel BUGs.
 *
 * Exit: 0 = PASS, 1 = FAIL
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include "common.h"

#define PAGE_SIZE       4096
#define NUM_PAGES       16
#define FILE_PATH       "intra_dedup_stress.dat"
#define SCANNER_WAIT    8

static int verify_page(int fd, int page_num, char expected)
{
    char buf[PAGE_SIZE];
    ssize_t nr;

    if (lseek(fd, (off_t)page_num * PAGE_SIZE, SEEK_SET) < 0) {
        perror("  lseek");
        return 1;
    }
    nr = read(fd, buf, PAGE_SIZE);
    if (nr != PAGE_SIZE) {
        fprintf(stderr, "  [FAIL] Page %d: short read (%zd)\n", page_num, nr);
        return 1;
    }
    for (int i = 0; i < PAGE_SIZE; i++) {
        if (buf[i] != expected) {
            fprintf(stderr, "  [FAIL] Page %d byte %d: expected '%c' (0x%02x), "
                    "got 0x%02x\n", page_num, i, expected,
                    (unsigned char)expected, (unsigned char)buf[i]);
            return 1;
        }
    }
    return 0;
}

int main(void)
{
    int ret = 0;
    int fd;

    printf("TEST: Intra-File Dedup Stress (16 identical pages in one file)\n");

    /* --- 1. Create file with 16 identical pages ----------------------- */
    char *blk = malloc(PAGE_SIZE);
    if (!blk) { perror("malloc"); return 1; }
    memset(blk, 'D', PAGE_SIZE);

    char *pages[NUM_PAGES];
    for (int i = 0; i < NUM_PAGES; i++)
        pages[i] = blk;

    printf("[*] Creating %d-page file with identical content...\n", NUM_PAGES);
    if (create_and_queue(FILE_PATH, pages, NUM_PAGES, PAGE_SIZE) < 0) {
        ret = 1;
        goto out;
    }

    /* --- 2. Wait for intra-file dedup --------------------------------- */
    printf("[*] Sleeping %ds for scanner to merge intra-file duplicates...\n",
           SCANNER_WAIT);
    sleep(SCANNER_WAIT);

    /* --- 3. Verify all 16 pages still read correctly ------------------ */
    printf("[*] Verifying all %d pages read back as 'D'...\n", NUM_PAGES);
    fd = open(FILE_PATH, O_RDONLY);
    if (fd < 0) { perror("open"); ret = 1; goto out; }
    for (int i = 0; i < NUM_PAGES; i++) {
        if (verify_page(fd, i, 'D') != 0) {
            close(fd);
            ret = 1;
            goto out;
        }
    }
    close(fd);
    printf("  -> All %d pages intact after dedup\n", NUM_PAGES);

    /* --- 4. Write different data to page 0 (COW breakout) ------------- */
    printf("[*] Writing 'W' to page 0 (COW break for one intra-file slot)...\n");
    fd = open(FILE_PATH, O_RDWR);
    if (fd < 0) { perror("open rw"); ret = 1; goto out; }
    char wbuf[PAGE_SIZE];
    memset(wbuf, 'W', PAGE_SIZE);
    ssize_t nw = write(fd, wbuf, PAGE_SIZE);
    if (nw != PAGE_SIZE) {
        perror("write page 0");
        close(fd);
        ret = 1;
        goto out;
    }
    fsync(fd);
    close(fd);

    /* --- 5. Verify page 0 = 'W', pages 1-15 = 'D' -------------------- */
    printf("[*] Verifying COW isolation...\n");
    fd = open(FILE_PATH, O_RDONLY);
    if (fd < 0) { perror("open verify"); ret = 1; goto out; }
    if (verify_page(fd, 0, 'W') != 0) {
        fprintf(stderr, "  [FAIL] Page 0 should be 'W' after write\n");
        close(fd);
        ret = 1;
        goto out;
    }
    for (int i = 1; i < NUM_PAGES; i++) {
        if (verify_page(fd, i, 'D') != 0) {
            fprintf(stderr, "  [FAIL] Page %d should still be 'D'\n", i);
            close(fd);
            ret = 1;
            goto out;
        }
    }
    close(fd);
    printf("  -> COW isolation verified: page 0 = 'W', pages 1-15 = 'D'\n");

    /* --- 6. Truncate to 8 pages (removes 8 intra-deduped slots) ------- */
    printf("[*] Truncating to 8 pages...\n");
    if (truncate(FILE_PATH, (off_t)8 * PAGE_SIZE) < 0) {
        perror("truncate to 8 pages");
        ret = 1;
        goto out;
    }

    /* --- 7. Verify remaining 8 pages ---------------------------------- */
    printf("[*] Verifying 8 remaining pages...\n");
    fd = open(FILE_PATH, O_RDONLY);
    if (fd < 0) { perror("open after trunc"); ret = 1; goto out; }
    if (verify_page(fd, 0, 'W') != 0) { close(fd); ret = 1; goto out; }
    for (int i = 1; i < 8; i++) {
        if (verify_page(fd, i, 'D') != 0) { close(fd); ret = 1; goto out; }
    }
    close(fd);
    printf("  -> 8 pages intact after partial truncation\n");

    /* --- 8. Truncate to 0 --------------------------------------------- */
    printf("[*] Truncating to 0 bytes...\n");
    if (truncate(FILE_PATH, 0) < 0) {
        perror("truncate to 0");
        ret = 1;
        goto out;
    }
    printf("  -> Truncate to 0 succeeded\n");

    /* --- 9. Delete — if nrpages leaked, kernel BUGs in clear_inode ---- */
    printf("[*] Deleting file (tests clear_inode nrpages == 0 invariant)...\n");
    if (unlink(FILE_PATH) < 0) {
        perror("unlink");
        ret = 1;
        goto out;
    }
    /* Small pause to let inode eviction run */
    usleep(500000);
    printf("  -> File deleted without kernel panic\n");

    if (ret == 0)
        printf("[PASS] Intra-file deduplication test passed\n");

out:
    free(blk);
    unlink(FILE_PATH);
    return ret;
}
