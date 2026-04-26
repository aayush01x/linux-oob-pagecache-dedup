/*
 * test_14_rapid_lifecycle.c
 *
 * RAPID DEDUP LIFECYCLE TEST
 *
 * Exercises the create-dedup-delete path in rapid succession to validate
 * correct handling of races between the scanner thread and file deletion:
 *
 *   1. In a tight loop (20 iterations):
 *      a. Create 2 identical files (8 pages each).
 *      b. Queue for dedup via fadvise.
 *      c. Sleep a SHORT time (1-2s) — scanner may or may not finish.
 *      d. Delete both files immediately.
 *      e. Wait for inode eviction.
 *
 * This exercises:
 *   - Deletion while scanner is mid-dedup (race on folio locks/rmap).
 *   - oob_dedup_evict_inode racing with oob_dedup_do_scan.
 *   - Stale hash table entries from partially-deduped files.
 *   - The scanner's igrab() returning NULL for dying inodes.
 *
 * If nrpages leaks or the scanner crashes, the kernel BUGs or panics.
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
#define ITERATIONS      20
#define SHORT_WAIT      2

int main(void)
{
    int ret = 0;

    printf("TEST: Rapid Dedup-and-Delete Cycle (%d iterations)\n", ITERATIONS);

    char *blk = malloc(PAGE_SIZE);
    if (!blk) { perror("malloc"); return 1; }

    char *pages[NUM_PAGES];

    for (int iter = 0; iter < ITERATIONS; iter++) {
        /* Use different fill each iteration to avoid stale hash matches */
        memset(blk, 'A' + (iter % 26), PAGE_SIZE);
        for (int i = 0; i < NUM_PAGES; i++) pages[i] = blk;

        char fa[64], fb[64];
        snprintf(fa, sizeof(fa), "rapid_%d_a.dat", iter);
        snprintf(fb, sizeof(fb), "rapid_%d_b.dat", iter);

        /* Create and queue */
        if (create_and_queue(fa, pages, NUM_PAGES, PAGE_SIZE) < 0 ||
            create_and_queue(fb, pages, NUM_PAGES, PAGE_SIZE) < 0) {
            ret = 1;
            unlink(fa); unlink(fb);
            break;
        }

        /* Short wait — scanner may be mid-dedup */
        usleep(SHORT_WAIT * 1000000 / ITERATIONS * (1 + (iter % 3)));

        /* Delete while potentially mid-dedup */
        unlink(fa);
        unlink(fb);

        /* Tiny pause for eviction */
        usleep(100000);

        if ((iter + 1) % 5 == 0)
            printf("  -> Completed %d/%d iterations\n", iter + 1, ITERATIONS);
    }

    /* If we get here without kernel BUG/panic, we passed */
    if (ret == 0)
        printf("[PASS] Rapid dedup-and-delete cycle completed\n");

    free(blk);

    /* Cleanup any stragglers */
    for (int i = 0; i < ITERATIONS; i++) {
        char fa[64], fb[64];
        snprintf(fa, sizeof(fa), "rapid_%d_a.dat", i);
        snprintf(fb, sizeof(fb), "rapid_%d_b.dat", i);
        unlink(fa); unlink(fb);
    }
    return ret;
}
