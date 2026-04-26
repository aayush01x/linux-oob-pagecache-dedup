/*
 * test_13_page_accounting.c
 *
 * PAGE ACCOUNTING CORRECTNESS VERIFICATION
 *
 * Bug: deduplicate_folio() decrements NR_FILE_PAGES for the dup_folio:
 *   lruvec_stat_mod_folio(dup_folio, NR_FILE_PAGES, -folio_nr_pages(dup_folio));
 * Then when the folio is later removed (truncate/evict), filemap_unaccount_folio()
 * decrements NR_FILE_PAGES AGAIN for the orig_folio sitting in that XArray slot.
 * Net effect: NR_FILE_PAGES underflows by 1 per deduped page.
 *
 * This test:
 *   1. Reads nr_file_pages from /proc/vmstat.
 *   2. Creates N identical files (100 pages each), queues for dedup.
 *   3. Waits for merge.
 *   4. Deletes all files.
 *   5. Reads nr_file_pages again.
 *   6. Compares: if final < baseline by more than a small margin, FAIL.
 *
 * Expected underflow = (N-1) * pages_per_file = 400 pages for 5 files × 100 pages.
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
#define NUM_PAGES       100
#define NUM_FILES       5
#define SCANNER_WAIT    12
#define SETTLE_WAIT     3

static const char *files[NUM_FILES] = {
    "nfp_a.dat", "nfp_b.dat", "nfp_c.dat", "nfp_d.dat", "nfp_e.dat",
};

static long read_nr_file_pages(void)
{
    FILE *f = fopen("/proc/vmstat", "r");
    if (!f) return -1;
    char line[256];
    long val = -1;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "nr_file_pages %ld", &val) == 1)
            break;
    }
    fclose(f);
    return val;
}

int main(void)
{
    int ret = 0;

    printf("TEST: NR_FILE_PAGES Stat Leak Detection\n");

    /* Drop caches to get a clean baseline */
    sync();
    int sfd = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (sfd >= 0) {
        write(sfd, "3\n", 2);
        close(sfd);
    }
    sleep(SETTLE_WAIT);

    long baseline = read_nr_file_pages();
    if (baseline < 0) {
        fprintf(stderr, "  [SKIP] Cannot read /proc/vmstat\n");
        return 0;
    }
    printf("[*] Baseline nr_file_pages: %ld\n", baseline);

    /* Create identical files */
    char *blk = malloc(PAGE_SIZE);
    memset(blk, 'N', PAGE_SIZE);
    char *pages[NUM_PAGES];
    for (int i = 0; i < NUM_PAGES; i++) pages[i] = blk;

    printf("[*] Creating %d identical %d-page files...\n", NUM_FILES, NUM_PAGES);
    for (int f = 0; f < NUM_FILES; f++) {
        if (create_and_queue(files[f], pages, NUM_PAGES, PAGE_SIZE) < 0) {
            ret = 1; goto out;
        }
    }

    long after_create = read_nr_file_pages();
    printf("[*] After create: nr_file_pages = %ld (delta +%ld)\n",
           after_create, after_create - baseline);

    /* Wait for dedup */
    printf("[*] Sleeping %ds for dedup...\n", SCANNER_WAIT);
    sleep(SCANNER_WAIT);

    long after_dedup = read_nr_file_pages();
    printf("[*] After dedup:  nr_file_pages = %ld (delta %ld from create)\n",
           after_dedup, after_dedup - after_create);

    /* Delete all files */
    printf("[*] Deleting all files...\n");
    for (int f = 0; f < NUM_FILES; f++) {
        unlink(files[f]);
    }
    sync();
    sleep(SETTLE_WAIT);

    /* Drop caches again */
    sfd = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (sfd >= 0) {
        write(sfd, "3\n", 2);
        close(sfd);
    }
    sleep(SETTLE_WAIT);

    long after_delete = read_nr_file_pages();
    printf("[*] After delete: nr_file_pages = %ld\n", after_delete);

    long leak = baseline - after_delete;
    printf("[*] Net change from baseline: %ld pages\n", -leak);

    /*
     * If NR_FILE_PAGES underflowed, after_delete will be LESS than baseline
     * by approximately (NUM_FILES - 1) * NUM_PAGES = 400 pages.
     * Allow small margin for background activity.
     */
    if (leak > 50) {
        fprintf(stderr, "  [FAIL] NR_FILE_PAGES underflowed by %ld pages!\n", leak);
        fprintf(stderr, "         Expected underflow ≈ %d (from double-decrement bug)\n",
                (NUM_FILES - 1) * NUM_PAGES);
        ret = 1;
    } else {
        printf("  -> NR_FILE_PAGES within acceptable range\n");
    }

    if (ret == 0)
        printf("[PASS] NR_FILE_PAGES leak test passed\n");
    else
        printf("[FAIL] NR_FILE_PAGES leak test FAILED\n");

out:
    free(blk);
    for (int f = 0; f < NUM_FILES; f++) unlink(files[f]);
    return ret;
}
