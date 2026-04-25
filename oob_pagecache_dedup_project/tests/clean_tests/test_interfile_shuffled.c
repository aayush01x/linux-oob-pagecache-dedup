/*
 * test_interfile_shuffled.c
 *
 * Creates N files, each containing the SAME set of unique pages but in
 * DIFFERENT (shuffled) order.  This guarantees:
 *   - NO intra-file dedup  (every page within a file is unique)
 *   - YES inter-file dedup (every page appears in all N files)
 *
 * After dedup, N files × P pages should collapse to just P physical pages.
 *
 * Usage:  sudo ./test_interfile_shuffled
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#ifndef POSIX_FADV_DEDUP
#define POSIX_FADV_DEDUP 8
#endif

#define NUM_FILES     10
#define NUM_PAGES     32   /* unique pages per file (small: 32 × 4K = 128K each) */
#define SCANNER_WAIT  45   /* seconds: need more time for split + re-scan */
#define SYSFS_THRESHOLD "/sys/kernel/oob_dedup/merge_threshold_pct"

/* Fisher-Yates shuffle */
static void shuffle(int *arr, int n)
{
    for (int i = n - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }
}

/*
 * Fill buf (of size pgsz) with a deterministic, unique pattern for page_id.
 */
static void fill_page(char *buf, long pgsz, int page_id)
{
    for (long i = 0; i < pgsz; i++)
        buf[i] = (char)((page_id * 37 + i * 7) & 0xFF);
    /* Stamp the page_id at the start for easy verification */
    memcpy(buf, &page_id, sizeof(page_id));
}

static int create_shuffled_file(const char *path, int *order, int npages, long pgsz)
{
    char *buf = malloc(pgsz);
    if (!buf) return -1;

    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        free(buf);
        return -1;
    }

    for (int i = 0; i < npages; i++) {
        fill_page(buf, pgsz, order[i]);
        if (write(fd, buf, pgsz) != pgsz) {
            perror("write");
            close(fd);
            free(buf);
            return -1;
        }
    }

    close(fd);
    free(buf);
    return 0;
}

static int verify_file(const char *path, int *order, int npages, long pgsz)
{
    char *expected = malloc(pgsz);
    char *actual = malloc(pgsz);
    if (!expected || !actual) { free(expected); free(actual); return -1; }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        free(expected); free(actual);
        return -1;
    }

    for (int i = 0; i < npages; i++) {
        fill_page(expected, pgsz, order[i]);

        if (read(fd, actual, pgsz) != pgsz) {
            perror("read");
            close(fd);
            free(expected); free(actual);
            return -1;
        }

        if (memcmp(expected, actual, pgsz) != 0) {
            fprintf(stderr, "  [FAIL] %s page %d (page_id=%d) content mismatch!\n",
                    path, i, order[i]);
            close(fd);
            free(expected); free(actual);
            return -1;
        }
    }

    close(fd);
    free(expected); free(actual);
    return 0;
}

int main(void)
{
    char filenames[NUM_FILES][64];
    int orders[NUM_FILES][NUM_PAGES];
    int ret = 0;
    long pgsz = sysconf(_SC_PAGESIZE);

    printf("=== Inter-File Shuffled Dedup Test ===\n");
    printf("  Files: %d, Pages/file: %d, Page size: %ld\n",
           NUM_FILES, NUM_PAGES, pgsz);
    printf("  Each file has %d UNIQUE pages (no intra-file dedup possible)\n",
           NUM_PAGES);
    printf("  All files share the same page set in DIFFERENT order\n\n");

    srand(42);  /* deterministic for reproducibility */

    /*
     * Lower merge_threshold so that even a 1-page partial match in a
     * large folio triggers a split.  After splitting, the scanner
     * re-visits the now order-0 pages and deduplicates them individually.
     */
    int orig_threshold = 50;
    FILE *sf = fopen(SYSFS_THRESHOLD, "r");
    if (sf) { fscanf(sf, "%d", &orig_threshold); fclose(sf); }
    sf = fopen(SYSFS_THRESHOLD, "w");
    if (sf) { fprintf(sf, "1"); fclose(sf); printf("  Set merge_threshold_pct = 1%%\n"); }
    else     { fprintf(stderr, "  Warning: cannot write %s\n", SYSFS_THRESHOLD); }

    /* --- Step 1: Generate file orders --- */
    for (int f = 0; f < NUM_FILES; f++) {
        snprintf(filenames[f], sizeof(filenames[f]),
                 "interfile_shuf_%d.dat", f + 1);

        /* Start with identity permutation */
        for (int p = 0; p < NUM_PAGES; p++)
            orders[f][p] = p;

        /* Shuffle (skip file 0 to keep one in-order for reference) */
        if (f > 0)
            shuffle(orders[f], NUM_PAGES);
    }

    /* Print first 3 files' page orders for visibility */
    for (int f = 0; f < 3 && f < NUM_FILES; f++) {
        printf("  File %d order: [", f + 1);
        for (int p = 0; p < NUM_PAGES && p < 8; p++)
            printf("%d%s", orders[f][p], p < 7 ? "," : "");
        if (NUM_PAGES > 8) printf(",...");
        printf("]\n");
    }
    printf("\n");

    /* --- Step 2: Create files --- */
    printf("[1] Creating %d shuffled files...\n", NUM_FILES);
    for (int f = 0; f < NUM_FILES; f++) {
        if (create_shuffled_file(filenames[f], orders[f], NUM_PAGES, pgsz) < 0) {
            fprintf(stderr, "  Failed to create %s\n", filenames[f]);
            ret = 1;
            goto cleanup;
        }
        printf("  Created %s\n", filenames[f]);
    }

    /* Flush + drop caches to clear fs private data */
    sync();
    if (system("echo 3 > /proc/sys/vm/drop_caches") != 0)
        fprintf(stderr, "  Warning: could not drop caches\n");
    sleep(1);

    /* --- Step 3: Read into page cache --- */
    printf("\n[2] Reading all files into page cache...\n");
    for (int f = 0; f < NUM_FILES; f++) {
        int fd = open(filenames[f], O_RDONLY);
        if (fd < 0) { perror("open"); ret = 1; goto cleanup; }
        char buf[4096];
        while (read(fd, buf, sizeof(buf)) > 0) {}
        close(fd);
    }

    /* --- Step 4: Queue for dedup --- */
    printf("[3] Queueing files for dedup...\n");
    for (int f = 0; f < NUM_FILES; f++) {
        int fd = open(filenames[f], O_RDONLY);
        if (fd < 0) { perror("open"); ret = 1; goto cleanup; }
        posix_fadvise(fd, 0, 0, POSIX_FADV_DEDUP);
        close(fd);
        printf("  Queued %s\n", filenames[f]);
    }

    /* --- Step 5: Wait for scanner --- */
    printf("\n[4] Waiting %ds for scanner...\n", SCANNER_WAIT);
    for (int i = 1; i <= SCANNER_WAIT; i++) {
        sleep(1);
        printf("\r    %d/%d seconds...", i, SCANNER_WAIT);
        fflush(stdout);
    }
    printf("\n\n");

    /* --- Step 6: Verify data integrity --- */
    printf("[5] Verifying all files (reading through deduped page cache)...\n");
    for (int f = 0; f < NUM_FILES; f++) {
        if (verify_file(filenames[f], orders[f], NUM_PAGES, pgsz) < 0) {
            fprintf(stderr, "  [FAIL] %s verification failed!\n", filenames[f]);
            ret = 1;
        } else {
            printf("  [PASS] %s: all %d pages correct\n",
                   filenames[f], NUM_PAGES);
        }
    }

    /* --- Step 7: Delete and check speed --- */
    printf("\n[6] Deleting all files (tests truncation of inter-file dedup)...\n");
    for (int f = 0; f < NUM_FILES; f++) {
        if (unlink(filenames[f]) < 0) {
            perror("unlink");
            ret = 1;
        } else {
            printf("  Deleted %s\n", filenames[f]);
        }
    }
    printf("  [+] All files deleted successfully.\n");

    printf("\n=== %s ===\n", ret == 0 ? "PASS" : "FAIL");

    /* Restore original threshold */
    sf = fopen(SYSFS_THRESHOLD, "w");
    if (sf) { fprintf(sf, "%d", orig_threshold); fclose(sf); }
    printf("  Restored merge_threshold_pct = %d%%\n", orig_threshold);

    return ret;

cleanup:
    for (int f = 0; f < NUM_FILES; f++)
        unlink(filenames[f]);
    return ret;
}
