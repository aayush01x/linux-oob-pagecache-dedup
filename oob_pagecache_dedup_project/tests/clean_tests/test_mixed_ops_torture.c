/*
 * test_mixed_ops_torture.c
 *
 * MIXED OPERATIONS TORTURE TEST
 *
 * The ultimate stress test — combines EVERY edge case into one scenario:
 *
 *   - Inter-file dedup (files A, B, C share content)
 *   - Intra-file dedup (file D has duplicate pages within itself)
 *   - Hole-punching (fallocate FALLOC_FL_PUNCH_HOLE on file A)
 *   - Partial truncation (truncate file B to mid-page boundary)
 *   - COW writes on file C while D is being deleted
 *   - Read verification on survivors throughout
 *   - Full cleanup (all files deleted, nrpages must be 0)
 *
 * This test is designed so that if ANY of these operations
 * has an off-by-one in nrpages, a stale rmap, a wrong XArray
 * slot removal, or a folio leak, it will manifest as either:
 *   - Data corruption (read verification fails)
 *   - Kernel BUG (clear_inode sees nrpages != 0)
 *   - Kernel NULL pointer dereference (bad mapping pointer)
 *   - Infinite loop in truncate_inode_pages_range
 *
 * Exit: 0 = PASS, 1 = FAIL
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include "common.h"

/* fallocate flags — define if not available in headers */
#ifndef FALLOC_FL_PUNCH_HOLE
#define FALLOC_FL_PUNCH_HOLE    0x02
#endif
#ifndef FALLOC_FL_KEEP_SIZE
#define FALLOC_FL_KEEP_SIZE     0x01
#endif

#define PAGE_SIZE       4096
#define INTER_PAGES     8      /* pages for inter-file dedup files */
#define INTRA_PAGES     12     /* pages for intra-file dedup file */
#define FILE_A          "torture_a.dat"
#define FILE_B          "torture_b.dat"
#define FILE_C          "torture_c.dat"
#define FILE_D          "torture_d.dat"  /* intra-file */
#define SCANNER_WAIT    10

static int verify_range(int fd, off_t offset, long len, char expected)
{
    char *buf = malloc(len);
    if (!buf) return 1;

    ssize_t nr = pread(fd, buf, len, offset);
    if (nr != len) {
        fprintf(stderr, "  [FAIL] pread at offset %ld: %zd vs %ld\n",
                (long)offset, nr, len);
        free(buf);
        return 1;
    }
    for (long i = 0; i < len; i++) {
        if (buf[i] != expected) {
            fprintf(stderr, "  [FAIL] offset %ld+%ld: expected '%c' (0x%02x), "
                    "got 0x%02x\n",
                    (long)offset, i, expected, (unsigned char)expected,
                    (unsigned char)buf[i]);
            free(buf);
            return 1;
        }
    }
    free(buf);
    return 0;
}

static int verify_range_zero(int fd, off_t offset, long len)
{
    char *buf = malloc(len);
    if (!buf) return 1;

    ssize_t nr = pread(fd, buf, len, offset);
    if (nr != len) {
        fprintf(stderr, "  [FAIL] pread at offset %ld: %zd vs %ld\n",
                (long)offset, nr, len);
        free(buf);
        return 1;
    }
    for (long i = 0; i < len; i++) {
        if (buf[i] != '\0') {
            fprintf(stderr, "  [FAIL] offset %ld+%ld: expected 0x00, got 0x%02x\n",
                    (long)offset, i, (unsigned char)buf[i]);
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
    long inter_size = (long)PAGE_SIZE * INTER_PAGES;
    long intra_size = (long)PAGE_SIZE * INTRA_PAGES;
    int fd;

    printf("TEST: Mixed Operations Torture\n");
    printf("  (inter-file dedup + intra-file dedup + hole-punch + "
           "partial truncate + COW + delete)\n\n");

    /* === Phase 1: Create all files ==================================== */
    char *blk_inter = malloc(PAGE_SIZE);
    char *blk_intra = malloc(PAGE_SIZE);
    if (!blk_inter || !blk_intra) { perror("malloc"); return 1; }
    memset(blk_inter, 'T', PAGE_SIZE);
    memset(blk_intra, 'I', PAGE_SIZE);

    /* Files A, B, C: identical inter-file content */
    char *inter_pages[INTER_PAGES];
    for (int i = 0; i < INTER_PAGES; i++)
        inter_pages[i] = blk_inter;

    /* File D: all pages identical (intra-file dedup candidate) */
    char *intra_pages[INTRA_PAGES];
    for (int i = 0; i < INTRA_PAGES; i++)
        intra_pages[i] = blk_intra;

    printf("[*] Creating 3 inter-file dedup files (%d pages each)...\n", INTER_PAGES);
    if (create_and_queue(FILE_A, inter_pages, INTER_PAGES, PAGE_SIZE) < 0) { ret = 1; goto out; }
    if (create_and_queue(FILE_B, inter_pages, INTER_PAGES, PAGE_SIZE) < 0) { ret = 1; goto out; }
    if (create_and_queue(FILE_C, inter_pages, INTER_PAGES, PAGE_SIZE) < 0) { ret = 1; goto out; }

    printf("[*] Creating 1 intra-file dedup file (%d identical pages)...\n", INTRA_PAGES);
    if (create_and_queue(FILE_D, intra_pages, INTRA_PAGES, PAGE_SIZE) < 0) { ret = 1; goto out; }

    /* === Phase 2: Wait for dedup ====================================== */
    printf("[*] Sleeping %ds for all dedup merges...\n", SCANNER_WAIT);
    sleep(SCANNER_WAIT);

    /* === Phase 3: Verify baseline ===================================== */
    printf("[*] Baseline verification...\n");
    fd = open(FILE_A, O_RDONLY);
    if (fd < 0) { perror("open A"); ret = 1; goto out; }
    if (verify_range(fd, 0, inter_size, 'T') != 0) { close(fd); ret = 1; goto out; }
    close(fd);
    printf("  -> A: OK\n");

    fd = open(FILE_D, O_RDONLY);
    if (fd < 0) { perror("open D"); ret = 1; goto out; }
    if (verify_range(fd, 0, intra_size, 'I') != 0) { close(fd); ret = 1; goto out; }
    close(fd);
    printf("  -> D: OK\n");

    /* === Phase 4: Hole-punch pages 2-3 of file A ====================== */
    printf("[*] Hole-punching pages 2-3 of %s...\n", FILE_A);
    fd = open(FILE_A, O_RDWR);
    if (fd < 0) { perror("open A rw"); ret = 1; goto out; }
    if (fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                  2 * PAGE_SIZE, 2 * PAGE_SIZE) < 0) {
        /* fallocate may not be supported on all filesystems */
        if (errno == EOPNOTSUPP) {
            printf("  -> fallocate not supported, skipping hole-punch\n");
        } else {
            perror("fallocate");
            close(fd);
            ret = 1;
            goto out;
        }
    } else {
        printf("  -> Hole punched\n");
        /* Verify: pages 0-1 = 'T', pages 2-3 = zeros, pages 4-7 = 'T' */
        if (verify_range(fd, 0, 2 * PAGE_SIZE, 'T') != 0) { close(fd); ret = 1; goto out; }
        if (verify_range_zero(fd, 2 * PAGE_SIZE, 2 * PAGE_SIZE) != 0) { close(fd); ret = 1; goto out; }
        if (verify_range(fd, 4 * PAGE_SIZE, 4 * PAGE_SIZE, 'T') != 0) { close(fd); ret = 1; goto out; }
        printf("  -> A after hole-punch: verified\n");
    }
    close(fd);

    /* Verify B and C are untouched by hole-punch on A */
    fd = open(FILE_B, O_RDONLY);
    if (verify_range(fd, 0, inter_size, 'T') != 0) {
        fprintf(stderr, "  [FAIL] B corrupted after hole-punch on A!\n");
        close(fd); ret = 1; goto out;
    }
    close(fd);
    printf("  -> B: still intact\n");

    fd = open(FILE_C, O_RDONLY);
    if (verify_range(fd, 0, inter_size, 'T') != 0) {
        fprintf(stderr, "  [FAIL] C corrupted after hole-punch on A!\n");
        close(fd); ret = 1; goto out;
    }
    close(fd);
    printf("  -> C: still intact\n");

    /* === Phase 5: Partial truncate file B to mid-page boundary ======== */
    long trunc_size = 3 * PAGE_SIZE + PAGE_SIZE / 2;  /* 3.5 pages */
    printf("[*] Truncating %s to %ld bytes (mid-page boundary)...\n",
           FILE_B, trunc_size);
    if (truncate(FILE_B, trunc_size) < 0) {
        perror("truncate B");
        ret = 1;
        goto out;
    }
    /* Verify: first 3.5 pages of B are 'T', rest gone */
    fd = open(FILE_B, O_RDONLY);
    if (fd < 0) { perror("open B after trunc"); ret = 1; goto out; }
    if (verify_range(fd, 0, 3 * PAGE_SIZE, 'T') != 0) { close(fd); ret = 1; goto out; }
    /* The partial page: first half should be 'T', second half zeroed by truncate */
    char *partial = malloc(PAGE_SIZE);
    ssize_t nr = pread(fd, partial, PAGE_SIZE / 2, 3 * PAGE_SIZE);
    if (nr != PAGE_SIZE / 2) {
        fprintf(stderr, "  [FAIL] Partial page read: %zd\n", nr);
        free(partial);
        close(fd);
        ret = 1;
        goto out;
    }
    for (int i = 0; i < PAGE_SIZE / 2; i++) {
        if (partial[i] != 'T') {
            fprintf(stderr, "  [FAIL] Partial page byte %d: expected 'T', got 0x%02x\n",
                    i, (unsigned char)partial[i]);
            free(partial);
            close(fd);
            ret = 1;
            goto out;
        }
    }
    free(partial);
    close(fd);
    printf("  -> B after partial truncate: verified\n");

    /* Verify C still intact */
    fd = open(FILE_C, O_RDONLY);
    if (verify_range(fd, 0, inter_size, 'T') != 0) {
        fprintf(stderr, "  [FAIL] C corrupted after B truncation!\n");
        close(fd); ret = 1; goto out;
    }
    close(fd);
    printf("  -> C: still intact\n");

    /* === Phase 6: COW write on file C while deleting file D =========== */
    printf("[*] Writing 'W' to page 0 of %s...\n", FILE_C);
    fd = open(FILE_C, O_RDWR);
    if (fd < 0) { perror("open C rw"); ret = 1; goto out; }
    char wbuf[PAGE_SIZE];
    memset(wbuf, 'W', PAGE_SIZE);
    if (write(fd, wbuf, PAGE_SIZE) != PAGE_SIZE) {
        perror("write C");
        close(fd);
        ret = 1;
        goto out;
    }
    fsync(fd);
    close(fd);

    printf("[*] Deleting intra-file dedup file %s...\n", FILE_D);
    if (unlink(FILE_D) < 0) {
        perror("unlink D");
        ret = 1;
        goto out;
    }
    usleep(500000);
    printf("  -> D deleted\n");

    /* Verify C: page 0 = 'W', pages 1-7 = 'T' */
    fd = open(FILE_C, O_RDONLY);
    if (fd < 0) { perror("open C verify"); ret = 1; goto out; }
    if (verify_range(fd, 0, PAGE_SIZE, 'W') != 0) { close(fd); ret = 1; goto out; }
    if (verify_range(fd, PAGE_SIZE, (INTER_PAGES - 1) * PAGE_SIZE, 'T') != 0) {
        close(fd); ret = 1; goto out;
    }
    close(fd);
    printf("  -> C after COW + D deletion: verified\n");

    /* === Phase 7: Delete everything =================================== */
    printf("[*] Deleting all remaining files...\n");
    unlink(FILE_A);
    usleep(200000);
    printf("  -> A deleted\n");
    unlink(FILE_B);
    usleep(200000);
    printf("  -> B deleted\n");
    unlink(FILE_C);
    usleep(200000);
    printf("  -> C deleted\n");

    /* If we reach here without kernel panic, nrpages was correct */
    printf("  -> All files deleted without kernel panic\n");

    if (ret == 0)
        printf("\n[PASS] Mixed operations torture test passed\n");

out:
    free(blk_inter);
    free(blk_intra);
    unlink(FILE_A);
    unlink(FILE_B);
    unlink(FILE_C);
    unlink(FILE_D);
    return ret;
}
