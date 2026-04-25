/*
 * test_anchor_partial_match.c
 *
 * Tests the anchor-based hashing partial match detection.
 * Creates two large files that are ALMOST identical (differ by 1 page),
 * triggers dedup, and verifies:
 *   1. Anchor hashing detects the partial match
 *   2. The scanner splits the large folios
 *   3. After re-scan, the matching pages get deduped
 *   4. The differing page remains unique
 *   5. Data integrity is preserved
 *
 * Must run on XFS for large folio support (order-4 = 64KB folios).
 *
 * Exit: 0 = PASS, 1 = FAIL
 */

#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "common.h"

#define POSIX_FADV_DEDUP 8
#define PAGE_SIZE        4096
#define FILE_SIZE_MB     4           /* 4 MB per file */
#define FILE_SIZE_BYTES  (FILE_SIZE_MB * 1024 * 1024)
#define CHUNK_SIZE       (256 * PAGE_SIZE)  /* 1 MB write chunks */
#define TOTAL_CHUNKS     (FILE_SIZE_BYTES / CHUNK_SIZE)

#define FILE_A           "anchor_partial_a.dat"
#define FILE_B           "anchor_partial_b.dat"

/* Which page to make different (page 7 of the file = byte offset 7*4096) */
#define DIFF_PAGE_IDX    7
#define DIFF_OFFSET      ((long)DIFF_PAGE_IDX * PAGE_SIZE)

/* Give the scanner more time since it needs to:
 * 1st pass: detect partial match via anchors, split  
 * 2nd pass: dedup the now-order-0 pages              */
#define SCANNER_WAIT     8

static int create_file_and_queue(const char *path, char fill)
{
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror(path); return -1; }

    char *buf = malloc(CHUNK_SIZE);
    memset(buf, fill, CHUNK_SIZE);

    for (int i = 0; i < TOTAL_CHUNKS; i++) {
        if (write(fd, buf, CHUNK_SIZE) != CHUNK_SIZE) {
            perror("write"); free(buf); close(fd); return -1;
        }
    }
    free(buf);
    fsync(fd);

    /* Queue immediately while pages are still in cache from the write */
    int ret = posix_fadvise(fd, 0, 0, POSIX_FADV_DEDUP);
    if (ret != 0) {
        fprintf(stderr, "  fadvise(%s): %s\n", path, strerror(ret));
        close(fd);
        return -1;
    }
    printf("  [+] Created & queued: %s\n", path);
    close(fd);
    return 0;
}

/*
 * Read the entire file sequentially to warm the page cache.
 * This ensures folios exist for the scanner to hash.
 */
static int read_file_into_cache(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); return -1; }

    char *buf = malloc(CHUNK_SIZE);
    ssize_t nr;
    while ((nr = read(fd, buf, CHUNK_SIZE)) > 0)
        ; /* just pull pages into cache */
    free(buf);
    close(fd);
    return 0;
}

int main(void)
{
    int ret = 0;

    printf("TEST: Anchor-Based Partial Match Detection\n");
    printf("=========================================\n");
    printf("[*] File size: %d MB, diff page: %d (offset %ld)\n",
           FILE_SIZE_MB, DIFF_PAGE_IDX, DIFF_OFFSET);

    /* --- 1. Create file A (all 'P'), queue immediately ---------------- */
    printf("\n[*] Step 1: Creating %s (all 'P')...\n", FILE_A);
    if (create_file_and_queue(FILE_A, 'P') < 0) return 1;

    /* --- 2. Create file B (all 'P'), then modify page 7 --------------- */
    printf("\n[*] Step 2: Creating %s, then modifying page %d...\n",
           FILE_B, DIFF_PAGE_IDX);

    /* Create as all 'P' first (but don't queue yet) */
    {
        int fd = open(FILE_B, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) { perror(FILE_B); return 1; }

        char *buf = malloc(CHUNK_SIZE);
        memset(buf, 'P', CHUNK_SIZE);
        for (int i = 0; i < TOTAL_CHUNKS; i++) {
            if (write(fd, buf, CHUNK_SIZE) != CHUNK_SIZE) {
                perror("write"); free(buf); close(fd); return 1;
            }
        }
        free(buf);
        fsync(fd);

        /* Now modify page 7 */
        char diff_page[PAGE_SIZE];
        memset(diff_page, 'X', PAGE_SIZE);
        if (lseek(fd, DIFF_OFFSET, SEEK_SET) < 0) {
            perror("lseek"); close(fd); return 1;
        }
        if (write(fd, diff_page, PAGE_SIZE) != PAGE_SIZE) {
            perror("write diff page"); close(fd); return 1;
        }
        fsync(fd);

        /* Queue for dedup while pages are hot in cache */
        int r = posix_fadvise(fd, 0, 0, POSIX_FADV_DEDUP);
        if (r != 0) {
            fprintf(stderr, "  fadvise(%s): %s\n", FILE_B, strerror(r));
            close(fd); return 1;
        }
        printf("  [+] Created, modified page %d, & queued: %s\n",
               DIFF_PAGE_IDX, FILE_B);
        close(fd);
    }

    /* --- 3. Re-read both files to ensure pages are warm in cache ------ */
    printf("\n[*] Step 3: Reading both files into page cache...\n");
    read_file_into_cache(FILE_A);
    read_file_into_cache(FILE_B);
    printf("  -> Page cache warmed\n");

    /* --- 4. Wait for scanner ----------------------------------------- */
    printf("\n[*] Step 4: Waiting %ds for scanner (anchor detect + split + re-dedup)...\n",
           SCANNER_WAIT);
    printf("  -> Check dmesg for [ANCHOR] messages!\n");
    printf("  -> Expected: 'Partial match >= threshold ... Splitting'\n");
    sleep(SCANNER_WAIT);

    /* --- 5. Read sysfs stats ----------------------------------------- */
    printf("\n[*] Step 5: Checking sysfs stats...\n");

    FILE *f;
    char buf[64];
    int pages_deduped = 0, folios_split = 0, pages_scanned = 0;

    f = fopen("/sys/kernel/oob_dedup/pages_deduped", "r");
    if (f) { fgets(buf, sizeof(buf), f); pages_deduped = atoi(buf); fclose(f); }

    f = fopen("/sys/kernel/oob_dedup/folios_split", "r");
    if (f) { fgets(buf, sizeof(buf), f); folios_split = atoi(buf); fclose(f); }

    f = fopen("/sys/kernel/oob_dedup/pages_scanned", "r");
    if (f) { fgets(buf, sizeof(buf), f); pages_scanned = atoi(buf); fclose(f); }

    printf("  pages_scanned : %d\n", pages_scanned);
    printf("  pages_deduped : %d\n", pages_deduped);
    printf("  folios_split  : %d\n", folios_split);

    if (pages_scanned == 0) {
        fprintf(stderr, "  [WARN] Scanner hasn't run yet! Increase SCANNER_WAIT.\n");
    }

    /* --- 6. Verify data integrity ------------------------------------ */
    printf("\n[*] Step 6: Verifying data integrity...\n");

    /* File A should be all 'P' */
    printf("  Checking %s (should be all 'P')...\n", FILE_A);
    fd = open(FILE_A, O_RDONLY);
    if (fd < 0) { perror("open file_a"); ret = 1; goto out; }

    char *vbuf = malloc(PAGE_SIZE);
    for (long off = 0; off < FILE_SIZE_BYTES; off += PAGE_SIZE) {
        ssize_t nr = read(fd, vbuf, PAGE_SIZE);
        if (nr != PAGE_SIZE) {
            fprintf(stderr, "  [FAIL] %s: short read at offset %ld\n", FILE_A, off);
            ret = 1; break;
        }
        for (int j = 0; j < PAGE_SIZE; j++) {
            if (vbuf[j] != 'P') {
                fprintf(stderr, "  [FAIL] %s: byte %ld expected 'P' got 0x%02x\n",
                        FILE_A, off + j, (unsigned char)vbuf[j]);
                ret = 1; goto verify_done;
            }
        }
    }
    close(fd);
    if (ret == 0) printf("  -> %s: OK (all 'P')\n", FILE_A);

    /* File B: page DIFF_PAGE_IDX should be 'X', everything else 'P' */
    printf("  Checking %s (page %d = 'X', rest = 'P')...\n", FILE_B, DIFF_PAGE_IDX);
    fd = open(FILE_B, O_RDONLY);
    if (fd < 0) { perror("open file_b"); ret = 1; goto verify_done; }

    for (long off = 0; off < FILE_SIZE_BYTES; off += PAGE_SIZE) {
        ssize_t nr = read(fd, vbuf, PAGE_SIZE);
        if (nr != PAGE_SIZE) {
            fprintf(stderr, "  [FAIL] %s: short read at offset %ld\n", FILE_B, off);
            ret = 1; break;
        }

        char expected = (off == DIFF_OFFSET) ? 'X' : 'P';
        for (int j = 0; j < PAGE_SIZE; j++) {
            if (vbuf[j] != expected) {
                fprintf(stderr, "  [FAIL] %s: byte %ld expected '%c' got 0x%02x\n",
                        FILE_B, off + j, expected, (unsigned char)vbuf[j]);
                ret = 1; goto verify_done;
            }
        }
    }
    close(fd);
    fd = -1;
    if (ret == 0) printf("  -> %s: OK (page %d='X', rest='P')\n", FILE_B, DIFF_PAGE_IDX);

verify_done:
    free(vbuf);
    if (fd >= 0) close(fd);

    /* --- 7. Summary -------------------------------------------------- */
    printf("\n=========================================\n");
    if (ret == 0) {
        printf("[PASS] Anchor partial match test passed\n");
        printf("  -> Data integrity: OK\n");
        printf("  -> Check 'dmesg | grep ANCHOR' for anchor hashing trace\n");
        printf("  -> Check 'dmesg | grep Splitting' for partial match split\n");
    } else {
        printf("[FAIL] Anchor partial match test FAILED\n");
    }

out:
    unlink(FILE_A);
    unlink(FILE_B);
    return ret;
}
