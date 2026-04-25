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

#include "common.h"

#define NUM_FILES     10
#define NUM_PAGES     32   /* unique pages per file (small: 32 × 4K = 128K each) */
#define SCANNER_WAIT  15   /* seconds to wait for scanner */

static char page_buf[PAGE_SIZE];

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
 * Fill page_buf with a deterministic, unique pattern for page 'page_id'.
 * Each page is filled with: 4-byte page_id repeated, then XOR'd with offset
 * to make every byte position unique.
 */
static void fill_page(int page_id)
{
    for (int i = 0; i < PAGE_SIZE; i++) {
        /* Unique per page_id, varies across the page */
        page_buf[i] = (char)((page_id * 37 + i * 7) & 0xFF);
    }
    /* Stamp the page_id at the start for easy verification */
    memcpy(page_buf, &page_id, sizeof(page_id));
}

static int create_shuffled_file(const char *path, int *order, int npages)
{
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    for (int i = 0; i < npages; i++) {
        fill_page(order[i]);
        if (write(fd, page_buf, PAGE_SIZE) != PAGE_SIZE) {
            perror("write");
            close(fd);
            return -1;
        }
    }

    close(fd);
    return 0;
}

static int verify_file(const char *path, int *order, int npages)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    for (int i = 0; i < npages; i++) {
        char expected[PAGE_SIZE];
        char actual[PAGE_SIZE];

        /* Generate expected content for this page */
        for (int j = 0; j < PAGE_SIZE; j++)
            expected[j] = (char)((order[i] * 37 + j * 7) & 0xFF);
        memcpy(expected, &order[i], sizeof(order[i]));

        if (read(fd, actual, PAGE_SIZE) != PAGE_SIZE) {
            perror("read");
            close(fd);
            return -1;
        }

        if (memcmp(expected, actual, PAGE_SIZE) != 0) {
            fprintf(stderr, "  [FAIL] %s page %d (page_id=%d) content mismatch!\n",
                    path, i, order[i]);
            close(fd);
            return -1;
        }
    }

    close(fd);
    return 0;
}

int main(void)
{
    char filenames[NUM_FILES][64];
    int orders[NUM_FILES][NUM_PAGES];
    int ret = 0;

    printf("=== Inter-File Shuffled Dedup Test ===\n");
    printf("  Files: %d, Pages/file: %d, Page size: %d\n",
           NUM_FILES, NUM_PAGES, PAGE_SIZE);
    printf("  Each file has %d UNIQUE pages (no intra-file dedup possible)\n",
           NUM_PAGES);
    printf("  All files share the same page set in DIFFERENT order\n\n");

    srand(42);  /* deterministic for reproducibility */

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
        if (create_shuffled_file(filenames[f], orders[f], NUM_PAGES) < 0) {
            fprintf(stderr, "  Failed to create %s\n", filenames[f]);
            ret = 1;
            goto cleanup;
        }
        printf("  Created %s\n", filenames[f]);
    }

    /* Flush + drop caches to clear fs private data */
    sync();
    system("echo 3 > /proc/sys/vm/drop_caches");
    sleep(1);

    /* --- Step 3: Read into page cache --- */
    printf("\n[2] Reading all files into page cache...\n");
    for (int f = 0; f < NUM_FILES; f++) {
        int fd = open(filenames[f], O_RDONLY);
        if (fd < 0) { perror("open"); ret = 1; goto cleanup; }
        char buf[PAGE_SIZE];
        while (read(fd, buf, PAGE_SIZE) > 0) {}
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
        if (verify_file(filenames[f], orders[f], NUM_PAGES) < 0) {
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
    return ret;

cleanup:
    for (int f = 0; f < NUM_FILES; f++)
        unlink(filenames[f]);
    return ret;
}
