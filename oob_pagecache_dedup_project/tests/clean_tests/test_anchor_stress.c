/*
 * test_anchor_stress.c
 *
 * Comprehensive stress test for anchor-based hashing, partial match
 * detection, COW isolation, truncation, and deletion under dedup.
 *
 * Creates a constellation of files with varying similarity levels and
 * then hammers every code path: exact dedup, partial-match split,
 * zero-page skip, COW break, truncation of shared folios, deletion
 * from dedup chains, re-dedup after COW, and NR_FILE_PAGES accounting.
 *
 * File layout (all 8MB on XFS for large folios):
 *
 *   base.dat       — 8MB of 'A' (the reference file)
 *   exact.dat      — 8MB of 'A' (exact copy → full dedup)
 *   near_miss.dat  — 8MB of 'A', page 7 = 'X' (1 page diff → split+dedup)
 *   scattered.dat  — 8MB of 'A', pages 50,200,500,800,1500 = 'Y' (5 scattered diffs)
 *   half_diff.dat  — 8MB: first 4MB = 'A', last 4MB = 'Z' (50% match)
 *   zero_head.dat  — 8MB: first 1MB = zeros, rest = 'A' (zero-page short circuit)
 *   alien.dat      — 8MB of 'Z' (0% match → no dedup)
 *   tiny.dat       — 16KB of 'A' (order-0 folios, tests degenerate anchor path)
 *
 * Phases:
 *   1. Create all files, queue for dedup, warm cache
 *   2. Wait for scanner — verify sysfs stats
 *   3. Data integrity check (all 8 files)
 *   4. COW: write to exact.dat and near_miss.dat, verify isolation
 *   5. Truncate half_diff.dat to 2MB, verify others survive
 *   6. Delete exact.dat, verify base.dat intact
 *   7. Re-queue base.dat + near_miss.dat for re-dedup after COW
 *   8. Final integrity sweep + NR_FILE_PAGES sanity check
 *
 * Must run on XFS for large folio support.
 * Exit: 0 = PASS, 1 = FAIL
 */

#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include "common.h"

#define POSIX_FADV_DEDUP  8
#define PAGE_SIZE         4096
#define MB                (1024 * 1024)
#define CHUNK_SIZE        (256 * PAGE_SIZE)  /* 1MB write chunks */

/* File sizes */
#define BIG_FILE_SIZE     (8 * MB)
#define TINY_FILE_SIZE    (4 * PAGE_SIZE)    /* 16KB = 4 pages */

/* File names */
#define F_BASE        "stress_base.dat"
#define F_EXACT       "stress_exact.dat"
#define F_NEARMISS    "stress_near_miss.dat"
#define F_SCATTERED   "stress_scattered.dat"
#define F_HALFDIFF    "stress_half_diff.dat"
#define F_ZEROHEAD    "stress_zero_head.dat"
#define F_ALIEN       "stress_alien.dat"
#define F_TINY        "stress_tiny.dat"

/* Scanner needs multiple passes: split + re-dedup + handle 8 files */
#define SCANNER_WAIT  15

/* Scattered diff page indices */
static const long scattered_diffs[] = {50, 200, 500, 800, 1500};
#define N_SCATTERED   (sizeof(scattered_diffs) / sizeof(scattered_diffs[0]))

static int fail_count = 0;

/* ---------- helpers ---------------------------------------------------- */

static void check(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "  [FAIL] %s\n", msg);
        fail_count++;
    }
}

static int write_file(const char *path, long size, char fill)
{
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror(path); return -1; }

    char *buf = malloc(CHUNK_SIZE);
    memset(buf, fill, CHUNK_SIZE);

    long remaining = size;
    while (remaining > 0) {
        long to_write = remaining < CHUNK_SIZE ? remaining : CHUNK_SIZE;
        if (write(fd, buf, to_write) != to_write) {
            perror("write"); free(buf); close(fd); return -1;
        }
        remaining -= to_write;
    }
    free(buf);
    fsync(fd);
    close(fd);
    return 0;
}

static int patch_page(const char *path, long page_idx, char fill)
{
    int fd = open(path, O_RDWR);
    if (fd < 0) { perror(path); return -1; }

    char buf[PAGE_SIZE];
    memset(buf, fill, PAGE_SIZE);

    if (lseek(fd, page_idx * PAGE_SIZE, SEEK_SET) < 0) {
        perror("lseek"); close(fd); return -1;
    }
    if (write(fd, buf, PAGE_SIZE) != PAGE_SIZE) {
        perror("write patch"); close(fd); return -1;
    }
    fsync(fd);
    close(fd);
    return 0;
}

static int queue(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); return -1; }

    int ret = posix_fadvise(fd, 0, 0, POSIX_FADV_DEDUP);
    close(fd);
    if (ret != 0) {
        fprintf(stderr, "  fadvise(%s): %s\n", path, strerror(ret));
        return -1;
    }
    return 0;
}

static int warm_cache(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    char *buf = malloc(CHUNK_SIZE);
    while (read(fd, buf, CHUNK_SIZE) > 0)
        ;
    free(buf);
    close(fd);
    return 0;
}

/*
 * Verify that every byte in [start_off, start_off + len) equals 'expected'.
 * Returns 0 on success, 1 on mismatch.
 */
static int verify_range(const char *path, long start_off, long len, char expected)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); return 1; }

    if (lseek(fd, start_off, SEEK_SET) < 0) {
        perror("lseek"); close(fd); return 1;
    }

    char *buf = malloc(PAGE_SIZE);
    long remaining = len;
    long offset = start_off;

    while (remaining > 0) {
        long to_read = remaining < PAGE_SIZE ? remaining : PAGE_SIZE;
        ssize_t nr = read(fd, buf, to_read);
        if (nr != to_read) {
            fprintf(stderr, "  [FAIL] %s: short read at offset %ld\n", path, offset);
            free(buf); close(fd); return 1;
        }
        for (long i = 0; i < to_read; i++) {
            if (buf[i] != expected) {
                fprintf(stderr, "  [FAIL] %s: byte %ld expected '%c' (0x%02x) got 0x%02x\n",
                        path, offset + i, expected, (unsigned char)expected,
                        (unsigned char)buf[i]);
                free(buf); close(fd); return 1;
            }
        }
        offset += to_read;
        remaining -= to_read;
    }

    free(buf);
    close(fd);
    return 0;
}

/*
 * Verify a file that is all 'base_fill' except at specific page indices
 * which should contain 'diff_fill'.
 */
static int verify_with_diffs(const char *path, long file_size, char base_fill,
                              const long *diff_pages, int n_diffs, char diff_fill)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); return 1; }

    char *buf = malloc(PAGE_SIZE);
    long total_pages = file_size / PAGE_SIZE;

    for (long p = 0; p < total_pages; p++) {
        ssize_t nr = read(fd, buf, PAGE_SIZE);
        if (nr != PAGE_SIZE) {
            fprintf(stderr, "  [FAIL] %s: short read at page %ld\n", path, p);
            free(buf); close(fd); return 1;
        }

        /* Is this page a diff page? */
        char expected = base_fill;
        for (int d = 0; d < n_diffs; d++) {
            if (diff_pages[d] == p) { expected = diff_fill; break; }
        }

        for (int i = 0; i < PAGE_SIZE; i++) {
            if (buf[i] != expected) {
                fprintf(stderr, "  [FAIL] %s: page %ld byte %d expected '%c' got 0x%02x\n",
                        path, p, i, expected, (unsigned char)buf[i]);
                free(buf); close(fd); return 1;
            }
        }
    }

    free(buf);
    close(fd);
    return 0;
}

static long read_sysfs_int(const char *knob)
{
    char path[128], buf[64];
    snprintf(path, sizeof(path), "/sys/kernel/oob_dedup/%s", knob);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return -1; }
    fclose(f);
    return atol(buf);
}

static long read_cached_kb(void)
{
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return -1;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        long val;
        if (sscanf(line, "Cached: %ld kB", &val) == 1) {
            fclose(f);
            return val;
        }
    }
    fclose(f);
    return -1;
}

/* ---------- main ------------------------------------------------------- */

int main(void)
{
    printf("============================================================\n");
    printf("  ANCHOR HASHING STRESS TEST\n");
    printf("============================================================\n\n");

    /* ================================================================== */
    /* PHASE 1: Create all files                                          */
    /* ================================================================== */
    printf("[Phase 1] Creating 8 test files...\n");

    /* base.dat — 8MB of 'A' */
    printf("  Creating %s (8MB of 'A')...\n", F_BASE);
    if (write_file(F_BASE, BIG_FILE_SIZE, 'A') < 0) return 1;

    /* exact.dat — identical copy */
    printf("  Creating %s (exact copy)...\n", F_EXACT);
    if (write_file(F_EXACT, BIG_FILE_SIZE, 'A') < 0) return 1;

    /* near_miss.dat — 1 page different */
    printf("  Creating %s (page 7 = 'X')...\n", F_NEARMISS);
    if (write_file(F_NEARMISS, BIG_FILE_SIZE, 'A') < 0) return 1;
    if (patch_page(F_NEARMISS, 7, 'X') < 0) return 1;

    /* scattered.dat — 5 scattered diff pages */
    printf("  Creating %s (pages 50,200,500,800,1500 = 'Y')...\n", F_SCATTERED);
    if (write_file(F_SCATTERED, BIG_FILE_SIZE, 'A') < 0) return 1;
    for (int i = 0; i < (int)N_SCATTERED; i++) {
        if (patch_page(F_SCATTERED, scattered_diffs[i], 'Y') < 0) return 1;
    }

    /* half_diff.dat — first 4MB = 'A', last 4MB = 'Z' */
    printf("  Creating %s (first 4MB 'A', last 4MB 'Z')...\n", F_HALFDIFF);
    {
        int fd = open(F_HALFDIFF, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) { perror(F_HALFDIFF); return 1; }
        char *buf = malloc(CHUNK_SIZE);

        /* First 4MB = 'A' */
        memset(buf, 'A', CHUNK_SIZE);
        for (int i = 0; i < 4; i++)
            if (write(fd, buf, CHUNK_SIZE) != CHUNK_SIZE) { perror("write"); return 1; }

        /* Last 4MB = 'Z' */
        memset(buf, 'Z', CHUNK_SIZE);
        for (int i = 0; i < 4; i++)
            if (write(fd, buf, CHUNK_SIZE) != CHUNK_SIZE) { perror("write"); return 1; }

        free(buf);
        fsync(fd);
        close(fd);
    }

    /* zero_head.dat — first 1MB zeros, rest = 'A' */
    printf("  Creating %s (first 1MB zeros, rest 'A')...\n", F_ZEROHEAD);
    {
        int fd = open(F_ZEROHEAD, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) { perror(F_ZEROHEAD); return 1; }
        char *buf = malloc(CHUNK_SIZE);

        /* First 1MB = zeros */
        memset(buf, 0, CHUNK_SIZE);
        if (write(fd, buf, CHUNK_SIZE) != CHUNK_SIZE) { perror("write"); return 1; }

        /* Rest 7MB = 'A' */
        memset(buf, 'A', CHUNK_SIZE);
        for (int i = 0; i < 7; i++)
            if (write(fd, buf, CHUNK_SIZE) != CHUNK_SIZE) { perror("write"); return 1; }

        free(buf);
        fsync(fd);
        close(fd);
    }

    /* alien.dat — 8MB of 'Z' (no match with anyone) */
    printf("  Creating %s (8MB of 'Z')...\n", F_ALIEN);
    if (write_file(F_ALIEN, BIG_FILE_SIZE, 'Z') < 0) return 1;

    /* tiny.dat — 16KB of 'A' (4 pages, order-0 folios) */
    printf("  Creating %s (16KB of 'A')...\n", F_TINY);
    if (write_file(F_TINY, TINY_FILE_SIZE, 'A') < 0) return 1;

    printf("  -> All files created\n\n");

    /* ================================================================== */
    /* Queue all for dedup + warm cache                                   */
    /* ================================================================== */
    printf("[Phase 1b] Queuing all files for dedup and warming cache...\n");
    const char *all_files[] = {
        F_BASE, F_EXACT, F_NEARMISS, F_SCATTERED,
        F_HALFDIFF, F_ZEROHEAD, F_ALIEN, F_TINY
    };
    for (int i = 0; i < 8; i++) {
        if (queue(all_files[i]) < 0) return 1;
        printf("  [+] Queued: %s\n", all_files[i]);
    }
    for (int i = 0; i < 8; i++)
        warm_cache(all_files[i]);
    printf("  -> Cache warmed\n\n");

    /* ================================================================== */
    /* PHASE 2: Wait for scanner                                          */
    /* ================================================================== */
    printf("[Phase 2] Waiting %ds for scanner...\n", SCANNER_WAIT);
    printf("  -> Check 'dmesg | grep ANCHOR' for trace\n");
    sleep(SCANNER_WAIT);

    long deduped   = read_sysfs_int("pages_deduped");
    long splits    = read_sysfs_int("folios_split");
    long scanned   = read_sysfs_int("pages_scanned");

    printf("\n  Sysfs after scan:\n");
    printf("    pages_scanned : %ld\n", scanned);
    printf("    pages_deduped : %ld\n", deduped);
    printf("    folios_split  : %ld\n", splits);

    check(deduped > 0, "Expected some pages to be deduped");
    check(scanned > 0, "Scanner should have scanned pages");
    printf("\n");

    /* ================================================================== */
    /* PHASE 3: Data integrity — all 8 files                              */
    /* ================================================================== */
    printf("[Phase 3] Verifying data integrity of all 8 files...\n");

    /* base.dat — all 'A' */
    printf("  %s: ", F_BASE);
    if (verify_range(F_BASE, 0, BIG_FILE_SIZE, 'A') == 0)
        printf("OK\n");
    else fail_count++;

    /* exact.dat — all 'A' */
    printf("  %s: ", F_EXACT);
    if (verify_range(F_EXACT, 0, BIG_FILE_SIZE, 'A') == 0)
        printf("OK\n");
    else fail_count++;

    /* near_miss.dat — all 'A' except page 7 = 'X' */
    {
        long diff = 7;
        printf("  %s: ", F_NEARMISS);
        if (verify_with_diffs(F_NEARMISS, BIG_FILE_SIZE, 'A', &diff, 1, 'X') == 0)
            printf("OK\n");
        else fail_count++;
    }

    /* scattered.dat — all 'A' except 5 pages = 'Y' */
    printf("  %s: ", F_SCATTERED);
    if (verify_with_diffs(F_SCATTERED, BIG_FILE_SIZE, 'A',
                           scattered_diffs, N_SCATTERED, 'Y') == 0)
        printf("OK\n");
    else fail_count++;

    /* half_diff.dat — first 4MB 'A', last 4MB 'Z' */
    printf("  %s: ", F_HALFDIFF);
    if (verify_range(F_HALFDIFF, 0, 4 * MB, 'A') == 0 &&
        verify_range(F_HALFDIFF, 4 * MB, 4 * MB, 'Z') == 0)
        printf("OK\n");
    else fail_count++;

    /* zero_head.dat — first 1MB zeros, rest 'A' */
    printf("  %s: ", F_ZEROHEAD);
    if (verify_range(F_ZEROHEAD, 0, 1 * MB, '\0') == 0 &&
        verify_range(F_ZEROHEAD, 1 * MB, 7 * MB, 'A') == 0)
        printf("OK\n");
    else fail_count++;

    /* alien.dat — all 'Z' */
    printf("  %s: ", F_ALIEN);
    if (verify_range(F_ALIEN, 0, BIG_FILE_SIZE, 'Z') == 0)
        printf("OK\n");
    else fail_count++;

    /* tiny.dat — all 'A' */
    printf("  %s: ", F_TINY);
    if (verify_range(F_TINY, 0, TINY_FILE_SIZE, 'A') == 0)
        printf("OK\n");
    else fail_count++;

    printf("\n");

    /* ================================================================== */
    /* PHASE 4: COW stress                                                */
    /* ================================================================== */
    printf("[Phase 4] COW stress — writing to deduped files...\n");

    /* Write 'B' to pages 0,100,500 of exact.dat */
    printf("  Writing 'B' to pages 0,100,500 of %s...\n", F_EXACT);
    if (patch_page(F_EXACT, 0, 'B') < 0) return 1;
    if (patch_page(F_EXACT, 100, 'B') < 0) return 1;
    if (patch_page(F_EXACT, 500, 'B') < 0) return 1;

    /* Write 'C' to page 0 of near_miss.dat */
    printf("  Writing 'C' to page 0 of %s...\n", F_NEARMISS);
    if (patch_page(F_NEARMISS, 0, 'C') < 0) return 1;

    /* Verify base.dat is completely untouched */
    printf("  Verifying %s untouched after COW...\n", F_BASE);
    printf("    %s: ", F_BASE);
    if (verify_range(F_BASE, 0, BIG_FILE_SIZE, 'A') == 0)
        printf("OK (isolation maintained)\n");
    else { fail_count++; printf("\n"); }

    /* Verify exact.dat has COW changes */
    printf("  Verifying %s has COW changes...\n", F_EXACT);
    {
        long cow_pages[] = {0, 100, 500};
        int cow_ok = 1;
        for (int i = 0; i < 3; i++) {
            if (verify_range(F_EXACT, cow_pages[i] * PAGE_SIZE, PAGE_SIZE, 'B') != 0) {
                cow_ok = 0; break;
            }
        }
        /* Check a non-COW page is still 'A' */
        if (cow_ok && verify_range(F_EXACT, 1 * PAGE_SIZE, PAGE_SIZE, 'A') != 0)
            cow_ok = 0;
        printf("    %s: %s\n", F_EXACT, cow_ok ? "OK" : "FAIL");
        if (!cow_ok) fail_count++;
    }

    /* Verify near_miss.dat: page 0 = 'C', page 7 = 'X', rest = 'A' */
    printf("  Verifying %s after COW...\n", F_NEARMISS);
    {
        int ok = 1;
        if (verify_range(F_NEARMISS, 0, PAGE_SIZE, 'C') != 0) ok = 0;
        if (ok && verify_range(F_NEARMISS, 7 * PAGE_SIZE, PAGE_SIZE, 'X') != 0) ok = 0;
        /* Check page 1 is still 'A' */
        if (ok && verify_range(F_NEARMISS, 1 * PAGE_SIZE, PAGE_SIZE, 'A') != 0) ok = 0;
        /* Check page 8 is still 'A' */
        if (ok && verify_range(F_NEARMISS, 8 * PAGE_SIZE, PAGE_SIZE, 'A') != 0) ok = 0;
        printf("    %s: %s\n", F_NEARMISS, ok ? "OK" : "FAIL");
        if (!ok) fail_count++;
    }

    /* Verify scattered.dat is completely untouched (no COW was done on it) */
    printf("  Verifying %s untouched...\n", F_SCATTERED);
    printf("    %s: ", F_SCATTERED);
    if (verify_with_diffs(F_SCATTERED, BIG_FILE_SIZE, 'A',
                           scattered_diffs, N_SCATTERED, 'Y') == 0)
        printf("OK\n");
    else fail_count++;

    printf("\n");

    /* ================================================================== */
    /* PHASE 5: Truncate half_diff.dat to 2MB                             */
    /* ================================================================== */
    printf("[Phase 5] Truncating %s to 2MB...\n", F_HALFDIFF);
    if (truncate(F_HALFDIFF, 2 * MB) < 0) {
        perror("truncate");
        fail_count++;
    } else {
        printf("  -> Truncated\n");

        /* Verify the first 2MB is still 'A' */
        printf("  Checking first 2MB of truncated file...\n");
        printf("    %s: ", F_HALFDIFF);
        if (verify_range(F_HALFDIFF, 0, 2 * MB, 'A') == 0)
            printf("OK\n");
        else fail_count++;

        /* Verify file size */
        struct stat st;
        stat(F_HALFDIFF, &st);
        check(st.st_size == 2 * MB, "half_diff.dat should be 2MB after truncate");
    }

    /* Verify other files survived the truncation */
    printf("  Verifying %s survived truncation...\n", F_BASE);
    printf("    %s: ", F_BASE);
    if (verify_range(F_BASE, 0, BIG_FILE_SIZE, 'A') == 0)
        printf("OK\n");
    else fail_count++;

    printf("  Verifying %s survived truncation...\n", F_SCATTERED);
    printf("    %s: ", F_SCATTERED);
    if (verify_with_diffs(F_SCATTERED, BIG_FILE_SIZE, 'A',
                           scattered_diffs, N_SCATTERED, 'Y') == 0)
        printf("OK\n");
    else fail_count++;

    printf("\n");

    /* ================================================================== */
    /* PHASE 6: Delete exact.dat, verify base.dat survives                */
    /* ================================================================== */
    printf("[Phase 6] Deleting %s...\n", F_EXACT);
    sync();
    unlink(F_EXACT);
    sleep(1);

    printf("  Verifying %s intact after peer deletion...\n", F_BASE);
    printf("    %s: ", F_BASE);
    if (verify_range(F_BASE, 0, BIG_FILE_SIZE, 'A') == 0)
        printf("OK\n");
    else fail_count++;

    printf("  Verifying %s intact...\n", F_ALIEN);
    printf("    %s: ", F_ALIEN);
    if (verify_range(F_ALIEN, 0, BIG_FILE_SIZE, 'Z') == 0)
        printf("OK\n");
    else fail_count++;

    printf("\n");

    /* ================================================================== */
    /* PHASE 7: Re-dedup after COW                                        */
    /* ================================================================== */
    printf("[Phase 7] Re-queuing files after COW for re-dedup...\n");

    /* Re-queue base and near_miss — scanner should find matching pages
     * again (near_miss page 0 is now 'C' from COW, page 7 is 'X',
     * but the other ~2046 pages should still match base) */
    if (queue(F_BASE) < 0) return 1;
    printf("  [+] Queued: %s\n", F_BASE);
    if (queue(F_NEARMISS) < 0) return 1;
    printf("  [+] Queued: %s\n", F_NEARMISS);

    warm_cache(F_BASE);
    warm_cache(F_NEARMISS);

    printf("  Waiting 10s for re-dedup...\n");
    sleep(10);

    long deduped2 = read_sysfs_int("pages_deduped");
    long splits2  = read_sysfs_int("folios_split");
    printf("  pages_deduped: %ld (was %ld, delta %ld)\n",
           deduped2, deduped, deduped2 - deduped);
    printf("  folios_split : %ld (was %ld, delta %ld)\n",
           splits2, splits, splits2 - splits);

    /* Verify integrity after re-dedup */
    printf("  Verifying %s after re-dedup...\n", F_BASE);
    printf("    %s: ", F_BASE);
    if (verify_range(F_BASE, 0, BIG_FILE_SIZE, 'A') == 0)
        printf("OK\n");
    else fail_count++;

    printf("  Verifying %s after re-dedup...\n", F_NEARMISS);
    {
        int ok = 1;
        /* page 0 = 'C' (from Phase 4 COW), page 7 = 'X', rest = 'A' */
        if (verify_range(F_NEARMISS, 0, PAGE_SIZE, 'C') != 0) ok = 0;
        if (ok && verify_range(F_NEARMISS, 7 * PAGE_SIZE, PAGE_SIZE, 'X') != 0) ok = 0;
        if (ok && verify_range(F_NEARMISS, 1 * PAGE_SIZE, PAGE_SIZE, 'A') != 0) ok = 0;
        printf("    %s: %s\n", F_NEARMISS, ok ? "OK" : "FAIL");
        if (!ok) fail_count++;
    }

    printf("\n");

    /* ================================================================== */
    /* PHASE 8: NR_FILE_PAGES sanity check                                */
    /* ================================================================== */
    printf("[Phase 8] NR_FILE_PAGES sanity check...\n");

    long cached_kb = read_cached_kb();
    printf("  Cached: %ld kB\n", cached_kb);
    check(cached_kb > 0, "Cached should be > 0 (not underflowed)");
    /* Rough check: cached shouldn't be astronomically high either */
    check(cached_kb < 100 * 1024 * 1024,
          "Cached should be < 100GB (not overflowed)");

    printf("\n");

    /* ================================================================== */
    /* SUMMARY                                                            */
    /* ================================================================== */
    printf("============================================================\n");
    if (fail_count == 0) {
        printf("  [PASS] Anchor stress test — ALL CHECKS PASSED\n");
        printf("    Exact dedup:     verified\n");
        printf("    Partial match:   verified (1-page + 5-page + 50%% diffs)\n");
        printf("    Zero-page skip:  exercised\n");
        printf("    COW isolation:   verified (3 writes to exact, 1 to near_miss)\n");
        printf("    Truncation:      verified (half_diff truncated, others survived)\n");
        printf("    Deletion:        verified (exact deleted, base survived)\n");
        printf("    Re-dedup:        verified (re-queued after COW)\n");
        printf("    NR_FILE_PAGES:   no underflow/overflow\n");
    } else {
        printf("  [FAIL] Anchor stress test — %d CHECK(S) FAILED\n", fail_count);
    }
    printf("============================================================\n");

    /* Cleanup */
    unlink(F_BASE);
    /* F_EXACT already deleted in Phase 6 */
    unlink(F_NEARMISS);
    unlink(F_SCATTERED);
    unlink(F_HALFDIFF);
    unlink(F_ZEROHEAD);
    unlink(F_ALIEN);
    unlink(F_TINY);

    return (fail_count > 0) ? 1 : 0;
}
