/*
 * test_03_delete_then_read.c
 *
 * Delete one of two deduped files, then read the surviving file and verify
 * data is intact. The existing test_delete.c only checks that deletion
 * doesn't crash; this test actually reads back the survivor.
 *
 * Scenario:
 *   1. Create file_a and file_b with identical content (multi-page).
 *   2. Queue both for dedup, wait for merge.
 *   3. Delete file_a via unlink().
 *   4. Read file_b and verify every byte matches the original pattern.
 *   5. Delete file_b and verify no crash.
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
#define NUM_PAGES     8
#define FILE_A        "del_read_a.dat"
#define FILE_B        "del_read_b.dat"
#define SCANNER_WAIT  5

int main(void)
{
    int ret = 0;

    printf("TEST: Delete Then Read Survivor\n");

    /* --- 1. Build page content (each page has a unique fill byte) ----- */
    char *page_bufs[NUM_PAGES];
    char *pages[NUM_PAGES];
    for (int i = 0; i < NUM_PAGES; i++) {
        page_bufs[i] = malloc(PAGE_SIZE);
        if (!page_bufs[i]) { perror("malloc"); return 1; }
        /* Use a different fill per page so corruption is detectable */
        memset(page_bufs[i], 'A' + (i % 26), PAGE_SIZE);
        pages[i] = page_bufs[i];
    }

    /* --- 2. Create identical files ------------------------------------ */
    printf("[*] Creating two identical %d-page files...\n", NUM_PAGES);
    if (create_and_queue(FILE_A, pages, NUM_PAGES, PAGE_SIZE) < 0) { ret = 1; goto out; }
    if (create_and_queue(FILE_B, pages, NUM_PAGES, PAGE_SIZE) < 0) { ret = 1; goto out; }

    /* --- 3. Wait for dedup -------------------------------------------- */
    printf("[*] Sleeping %ds for background merge...\n", SCANNER_WAIT);
    sleep(SCANNER_WAIT);

    /* --- 4. Delete file_a --------------------------------------------- */
    printf("[*] Deleting %s...\n", FILE_A);
    if (unlink(FILE_A) != 0) {
        perror("unlink file_a");
        ret = 1;
        goto out;
    }
    printf("  -> Deleted OK\n");

    /* Small pause to let eviction complete */
    usleep(500000);

    /* --- 5. Read and verify file_b ------------------------------------ */
    printf("[*] Reading back %s to verify integrity...\n", FILE_B);
    int fd = open(FILE_B, O_RDONLY);
    if (fd < 0) { perror("open file_b"); ret = 1; goto out; }

    char *vbuf = malloc(PAGE_SIZE);
    if (!vbuf) { perror("malloc vbuf"); close(fd); ret = 1; goto out; }

    for (int pg = 0; pg < NUM_PAGES; pg++) {
        ssize_t nr = read(fd, vbuf, PAGE_SIZE);
        if (nr != PAGE_SIZE) {
            fprintf(stderr, "  [FAIL] Page %d: short read (%zd)\n", pg, nr);
            ret = 1;
            break;
        }
        char expected = 'A' + (pg % 26);
        if (memcmp(vbuf, page_bufs[pg], PAGE_SIZE) != 0) {
            fprintf(stderr, "  [FAIL] Page %d: content mismatch (expected fill 0x%02x)\n",
                    pg, (unsigned char)expected);
            ret = 1;
            break;
        }
        printf("  -> Page %d (fill '%c'): OK\n", pg, expected);
    }
    close(fd);
    free(vbuf);

    if (ret != 0)
        goto out;

    printf("  -> FILE_B: All %d pages intact after FILE_A deletion\n", NUM_PAGES);

    /* --- 6. Delete survivor too --------------------------------------- */
    printf("[*] Deleting survivor %s...\n", FILE_B);
    if (unlink(FILE_B) != 0) {
        perror("unlink file_b");
        ret = 1;
        goto out;
    }
    printf("  -> Deleted OK\n");

    if (ret == 0)
        printf("[PASS] Delete-then-read test passed\n");

out:
    for (int i = 0; i < NUM_PAGES; i++)
        free(page_bufs[i]);
    /* Safety unlinks in case of early failure */
    unlink(FILE_A);
    unlink(FILE_B);
    return ret;
}
