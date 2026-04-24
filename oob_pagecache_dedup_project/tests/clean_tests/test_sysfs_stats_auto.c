/*
 * test_sysfs_stats_auto.c
 *
 * Automated sysfs stats test: run a dedup workload, then read
 * /sys/kernel/oob_dedup/pages_deduped and assert it is > 0.
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
#define NUM_PAGES     16
#define FILE1         "sysfs_stat_1.dat"
#define FILE2         "sysfs_stat_2.dat"
#define SCANNER_WAIT  5
#define SYSFS_BASE    "/sys/kernel/oob_dedup/"

static long read_sysfs_long(const char *attr)
{
    char path[256];
    snprintf(path, sizeof(path), "%s%s", SYSFS_BASE, attr);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    long val = -1;
    fscanf(f, "%ld", &val);
    fclose(f);
    return val;
}

int main(void)
{
    int ret = 0;
    printf("TEST: Sysfs Stats (Automated)\n");

    long deduped_before = read_sysfs_long("pages_deduped");
    long scanned_before = read_sysfs_long("pages_scanned");
    if (deduped_before < 0 || scanned_before < 0) {
        fprintf(stderr, "  [FAIL] Cannot read baseline sysfs stats\n");
        return 1;
    }
    printf("[*] Baseline: scanned=%ld deduped=%ld\n", scanned_before, deduped_before);

    char *blk = malloc(PAGE_SIZE);
    memset(blk, 'S', PAGE_SIZE);
    char *pages[NUM_PAGES];
    for (int i = 0; i < NUM_PAGES; i++) pages[i] = blk;

    printf("[*] Creating two identical %d-page files...\n", NUM_PAGES);
    if (create_and_queue(FILE1, pages, NUM_PAGES, PAGE_SIZE) < 0) { ret = 1; goto out; }
    if (create_and_queue(FILE2, pages, NUM_PAGES, PAGE_SIZE) < 0) { ret = 1; goto out; }

    printf("[*] Sleeping %ds for scanner...\n", SCANNER_WAIT);
    sleep(SCANNER_WAIT);

    long deduped_after = read_sysfs_long("pages_deduped");
    long scanned_after = read_sysfs_long("pages_scanned");
    long dd = deduped_after - deduped_before;
    long ds = scanned_after - scanned_before;
    printf("[*] After: scanned=%ld (+%ld) deduped=%ld (+%ld)\n",
           scanned_after, ds, deduped_after, dd);

    if (ds <= 0) { fprintf(stderr, "  [FAIL] pages_scanned did not increase\n"); ret = 1; }
    else printf("  -> pages_scanned +%ld: OK\n", ds);

    if (dd <= 0) { fprintf(stderr, "  [FAIL] pages_deduped did not increase\n"); ret = 1; }
    else printf("  -> pages_deduped +%ld: OK\n", dd);

    if (ret == 0) printf("[PASS] Sysfs stats test passed\n");
out:
    free(blk);
    unlink(FILE1);
    unlink(FILE2);
    return ret;
}
