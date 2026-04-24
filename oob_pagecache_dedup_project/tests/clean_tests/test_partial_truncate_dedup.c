/*
 * test_partial_truncate_dedup.c
 *
 * PARTIAL TRUNCATION OF DEDUPED FOLIOS — exercises truncate_inode_partial_folio
 *
 * truncate_inode_partial_folio() is called from truncate_inode_pages_range()
 * whenever the truncation boundary falls MID-PAGE (not page-aligned).
 * For deduped folios this is especially dangerous because:
 *
 *   1. folio_mapping(folio) must resolve through the rmap_list (tagged pointer)
 *      instead of folio->mapping (which points to oob_dedup_info, not an
 *      address_space).
 *   2. folio_pos_near(folio, mapping, target_index) must find the correct
 *      rmap entry — especially tricky for intra-file dedup where multiple
 *      entries share the same mapping.
 *   3. After zeroing the partial range, if length == folio_size the function
 *      calls truncate_inode_folio() which goes through the full remove path.
 *   4. The folio_wait_writeback() + folio_invalidate() + folio_zero_range()
 *      sequence all dereference the mapping, so a bad mapping pointer will
 *      oops immediately.
 *
 * This test exercises FIVE distinct partial-truncation scenarios on deduped
 * folios, in escalating difficulty:
 *
 *   Scenario A: Inter-file dedup — truncate to mid-page.
 *     Two files share folios. ftruncate file_a to 3.5 pages (14336 bytes).
 *     truncate_inode_partial_folio runs on the folio at page index 3.
 *     Verify file_b is completely untouched.
 *
 *   Scenario B: Inter-file dedup — truncate to byte 1 of page 0.
 *     ftruncate file_a to 1 byte. The entire file is now 1 byte; this
 *     means truncate_inode_partial_folio is called on page 0's folio
 *     with offset=1, length=4095 — maximum partial zeroing.
 *     Verify file_b is intact.
 *
 *   Scenario C: Intra-file dedup — truncate to mid-page.
 *     A single file has 8 identical pages. After dedup, multiple XArray
 *     slots in the same mapping point to the same physical folio.
 *     ftruncate to 5.5 pages. The partial folio at index 5 is shared
 *     with other slots in the same file — folio_pos_near must pick
 *     the correct rmap entry for index 5 (not index 0 or 1).
 *
 *   Scenario D: Successive partial truncations.
 *     Start with deduped file at 8 pages, truncate to 7.5, then 7.25,
 *     then 6.5, then 5.0, then 4.75, then 3.5, then 2.0, then 0.
 *     Each step calls truncate_inode_partial_folio. The folio's dedup
 *     state changes as rmap entries are removed during the shrink.
 *
 *   Scenario E: Partial truncation followed by write and re-read.
 *     Truncate deduped file to mid-page, write new data to the truncated
 *     region (extending the file back), verify no corruption of the
 *     surviving partner file.
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

#define PAGE_SIZE       4096
#define SCANNER_WAIT    8
#define POSIX_FADV_DEDUP 8

static int verify_range(const char *path, off_t offset, long len, char expected)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); return 1; }
    char *buf = malloc(len);
    if (!buf) { close(fd); return 1; }
    ssize_t nr = pread(fd, buf, len, offset);
    close(fd);
    if (nr != len) {
        fprintf(stderr, "  [FAIL] %s: pread at %ld: %zd vs %ld\n",
                path, (long)offset, nr, len);
        free(buf);
        return 1;
    }
    for (long i = 0; i < len; i++) {
        if (buf[i] != expected) {
            fprintf(stderr, "  [FAIL] %s offset %ld+%ld: expected '%c' (0x%02x), "
                    "got 0x%02x\n", path, (long)offset, i, expected,
                    (unsigned char)expected, (unsigned char)buf[i]);
            free(buf);
            return 1;
        }
    }
    free(buf);
    return 0;
}

static int verify_file_size(const char *path, off_t expected_size)
{
    struct stat st;
    if (stat(path, &st) < 0) { perror(path); return 1; }
    if (st.st_size != expected_size) {
        fprintf(stderr, "  [FAIL] %s size: expected %ld, got %ld\n",
                path, (long)expected_size, (long)st.st_size);
        return 1;
    }
    return 0;
}

int main(void)
{
    int ret = 0;
    int fd;

    printf("TEST: Partial Truncation of Deduped Folios\n");
    printf("  (directly exercises truncate_inode_partial_folio)\n\n");

    /* ================================================================== */
    /* SCENARIO A: Inter-file dedup, truncate to mid-page (3.5 pages)     */
    /* ================================================================== */
    printf("=== Scenario A: Inter-file, truncate to 3.5 pages ===\n");
    {
        const char *fa = "parttrunc_a1.dat";
        const char *fb = "parttrunc_b1.dat";
        int num_pages = 8;
        long file_size = (long)PAGE_SIZE * num_pages;
        off_t trunc_to = 3 * PAGE_SIZE + PAGE_SIZE / 2; /* 14336 bytes */

        char *blk = malloc(PAGE_SIZE);
        memset(blk, 'P', PAGE_SIZE);
        char *pages[8];
        for (int i = 0; i < num_pages; i++) pages[i] = blk;

        if (create_and_queue(fa, pages, num_pages, PAGE_SIZE) < 0 ||
            create_and_queue(fb, pages, num_pages, PAGE_SIZE) < 0) {
            free(blk); ret = 1; goto cleanup_a;
        }
        free(blk);

        printf("[*] Sleeping %ds for dedup...\n", SCANNER_WAIT);
        sleep(SCANNER_WAIT);

        /* Truncate file_a to mid-page: triggers truncate_inode_partial_folio */
        printf("[*] ftruncate %s to %ld bytes (mid-page)...\n", fa, (long)trunc_to);
        fd = open(fa, O_RDWR);
        if (fd < 0) { perror("open"); ret = 1; goto cleanup_a; }
        if (ftruncate(fd, trunc_to) < 0) {
            perror("ftruncate A to mid-page");
            close(fd); ret = 1; goto cleanup_a;
        }
        close(fd);

        /* Verify file_a: first 3.5 pages of 'P' */
        if (verify_file_size(fa, trunc_to) != 0) { ret = 1; goto cleanup_a; }
        if (verify_range(fa, 0, trunc_to, 'P') != 0) { ret = 1; goto cleanup_a; }
        printf("  -> %s: %ld bytes of 'P' verified\n", fa, (long)trunc_to);

        /* Verify file_b: completely untouched */
        if (verify_range(fb, 0, file_size, 'P') != 0) {
            fprintf(stderr, "  [FAIL] %s corrupted by partial truncation of %s!\n",
                    fb, fa);
            ret = 1; goto cleanup_a;
        }
        printf("  -> %s: all %ld bytes intact (dedup isolation OK)\n", fb, file_size);
        printf("  -> Scenario A: PASS\n\n");

cleanup_a:
        unlink("parttrunc_a1.dat");
        unlink("parttrunc_b1.dat");
        if (ret) return ret;
    }

    /* ================================================================== */
    /* SCENARIO B: Inter-file dedup, truncate to 1 byte (maximum partial) */
    /* ================================================================== */
    printf("=== Scenario B: Inter-file, truncate to 1 byte ===\n");
    {
        const char *fa = "parttrunc_a2.dat";
        const char *fb = "parttrunc_b2.dat";
        int num_pages = 4;
        long file_size = (long)PAGE_SIZE * num_pages;

        char *blk = malloc(PAGE_SIZE);
        memset(blk, 'Q', PAGE_SIZE);
        char *pages[4];
        for (int i = 0; i < num_pages; i++) pages[i] = blk;

        if (create_and_queue(fa, pages, num_pages, PAGE_SIZE) < 0 ||
            create_and_queue(fb, pages, num_pages, PAGE_SIZE) < 0) {
            free(blk); ret = 1; goto cleanup_b;
        }
        free(blk);

        sleep(SCANNER_WAIT);

        /* Truncate to 1 byte: offset=1, length=4095 on page 0's folio */
        printf("[*] ftruncate %s to 1 byte (maximum partial zero)...\n", fa);
        fd = open(fa, O_RDWR);
        if (fd < 0) { perror("open"); ret = 1; goto cleanup_b; }
        if (ftruncate(fd, 1) < 0) {
            perror("ftruncate to 1 byte");
            close(fd); ret = 1; goto cleanup_b;
        }
        close(fd);

        /* Verify file_a is 1 byte of 'Q' */
        if (verify_file_size(fa, 1) != 0) { ret = 1; goto cleanup_b; }
        fd = open(fa, O_RDONLY);
        if (fd < 0) { perror("open"); ret = 1; goto cleanup_b; }
        char byte;
        if (read(fd, &byte, 1) != 1 || byte != 'Q') {
            fprintf(stderr, "  [FAIL] Single byte should be 'Q', got 0x%02x\n",
                    (unsigned char)byte);
            close(fd); ret = 1; goto cleanup_b;
        }
        close(fd);
        printf("  -> %s: 1 byte of 'Q' verified\n", fa);

        /* Verify file_b untouched */
        if (verify_range(fb, 0, file_size, 'Q') != 0) {
            fprintf(stderr, "  [FAIL] %s corrupted!\n", fb);
            ret = 1; goto cleanup_b;
        }
        printf("  -> %s: intact\n", fb);
        printf("  -> Scenario B: PASS\n\n");

cleanup_b:
        unlink("parttrunc_a2.dat");
        unlink("parttrunc_b2.dat");
        if (ret) return ret;
    }

    /* ================================================================== */
    /* SCENARIO C: Intra-file dedup, truncate to mid-page                 */
    /* ================================================================== */
    printf("=== Scenario C: Intra-file dedup, truncate to 5.5 pages ===\n");
    {
        const char *f = "parttrunc_intra.dat";
        int num_pages = 8;
        off_t trunc_to = 5 * PAGE_SIZE + PAGE_SIZE / 2; /* 22528 bytes */

        char *blk = malloc(PAGE_SIZE);
        memset(blk, 'J', PAGE_SIZE);
        char *pages[8];
        for (int i = 0; i < num_pages; i++) pages[i] = blk;

        if (create_and_queue(f, pages, num_pages, PAGE_SIZE) < 0) {
            free(blk); ret = 1; goto cleanup_c;
        }
        free(blk);

        printf("[*] Sleeping %ds for intra-file dedup...\n", SCANNER_WAIT);
        sleep(SCANNER_WAIT);

        /* Verify baseline */
        if (verify_range(f, 0, (long)num_pages * PAGE_SIZE, 'J') != 0) {
            ret = 1; goto cleanup_c;
        }

        /*
         * Truncate to 5.5 pages: truncate_inode_partial_folio called on
         * the folio at page index 5. For intra-file dedup, this folio is
         * shared with indices 0-4 and 6-7. folio_pos_near must pick
         * the rmap entry for index 5, not index 0.
         */
        printf("[*] ftruncate %s to %ld bytes...\n", f, (long)trunc_to);
        if (truncate(f, trunc_to) < 0) {
            perror("truncate intra to 5.5 pages");
            ret = 1; goto cleanup_c;
        }

        /* Verify: first 5.5 pages should be 'J' */
        if (verify_file_size(f, trunc_to) != 0) { ret = 1; goto cleanup_c; }
        if (verify_range(f, 0, trunc_to, 'J') != 0) { ret = 1; goto cleanup_c; }
        printf("  -> %ld bytes of 'J' verified after intra-file partial truncate\n",
               (long)trunc_to);

        /* Delete — if nrpages is wrong, kernel BUGs */
        printf("[*] Deleting %s...\n", f);
        unlink(f);
        usleep(500000);
        printf("  -> Deleted OK\n");
        printf("  -> Scenario C: PASS\n\n");

cleanup_c:
        unlink("parttrunc_intra.dat");
        if (ret) return ret;
    }

    /* ================================================================== */
    /* SCENARIO D: Successive partial truncations                         */
    /* ================================================================== */
    printf("=== Scenario D: Successive partial truncations ===\n");
    {
        const char *fa = "parttrunc_a4.dat";
        const char *fb = "parttrunc_b4.dat";
        int num_pages = 8;
        long file_size = (long)PAGE_SIZE * num_pages;

        char *blk = malloc(PAGE_SIZE);
        memset(blk, 'S', PAGE_SIZE);
        char *pages[8];
        for (int i = 0; i < num_pages; i++) pages[i] = blk;

        if (create_and_queue(fa, pages, num_pages, PAGE_SIZE) < 0 ||
            create_and_queue(fb, pages, num_pages, PAGE_SIZE) < 0) {
            free(blk); ret = 1; goto cleanup_d;
        }
        free(blk);

        sleep(SCANNER_WAIT);

        /*
         * Each truncation hits truncate_inode_partial_folio on the boundary
         * page's folio, which is deduped with file_b.
         */
        off_t steps[] = {
            7 * PAGE_SIZE + PAGE_SIZE / 2,      /* 7.5 pages */
            7 * PAGE_SIZE + PAGE_SIZE / 4,      /* 7.25 pages */
            6 * PAGE_SIZE + PAGE_SIZE / 2,      /* 6.5 pages */
            5 * PAGE_SIZE,                       /* 5.0 pages (aligned) */
            4 * PAGE_SIZE + PAGE_SIZE * 3 / 4,  /* 4.75 pages */
            3 * PAGE_SIZE + PAGE_SIZE / 2,      /* 3.5 pages */
            2 * PAGE_SIZE,                       /* 2.0 pages (aligned) */
            0                                    /* 0 bytes */
        };
        int nsteps = sizeof(steps) / sizeof(steps[0]);

        for (int s = 0; s < nsteps; s++) {
            printf("[*] Step %d: truncate %s to %ld bytes...\n",
                   s + 1, fa, (long)steps[s]);

            if (truncate(fa, steps[s]) < 0) {
                perror("truncate step");
                ret = 1; goto cleanup_d;
            }

            if (steps[s] > 0) {
                if (verify_file_size(fa, steps[s]) != 0) { ret = 1; goto cleanup_d; }
                if (verify_range(fa, 0, steps[s], 'S') != 0) { ret = 1; goto cleanup_d; }
                printf("  -> %s: %ld bytes OK\n", fa, (long)steps[s]);
            } else {
                if (verify_file_size(fa, 0) != 0) { ret = 1; goto cleanup_d; }
                printf("  -> %s: empty\n", fa);
            }

            /* Verify file_b is ALWAYS intact — every single step */
            if (verify_range(fb, 0, file_size, 'S') != 0) {
                fprintf(stderr, "  [FAIL] %s corrupted after step %d!\n",
                        fb, s + 1);
                ret = 1; goto cleanup_d;
            }
        }

        printf("  -> All %d steps completed, %s always intact\n", nsteps, fb);

        /* Delete both */
        unlink(fa);
        unlink(fb);
        usleep(500000);
        printf("  -> Scenario D: PASS\n\n");

cleanup_d:
        unlink("parttrunc_a4.dat");
        unlink("parttrunc_b4.dat");
        if (ret) return ret;
    }

    /* ================================================================== */
    /* SCENARIO E: Partial truncate then extend with write                */
    /* ================================================================== */
    printf("=== Scenario E: Partial truncate then extend with write ===\n");
    {
        const char *fa = "parttrunc_a5.dat";
        const char *fb = "parttrunc_b5.dat";
        int num_pages = 6;
        long file_size = (long)PAGE_SIZE * num_pages;
        off_t trunc_to = 4 * PAGE_SIZE + 1000; /* mid-page boundary */

        char *blk = malloc(PAGE_SIZE);
        memset(blk, 'E', PAGE_SIZE);
        char *pages[6];
        for (int i = 0; i < num_pages; i++) pages[i] = blk;

        if (create_and_queue(fa, pages, num_pages, PAGE_SIZE) < 0 ||
            create_and_queue(fb, pages, num_pages, PAGE_SIZE) < 0) {
            free(blk); ret = 1; goto cleanup_e;
        }
        free(blk);

        sleep(SCANNER_WAIT);

        /* Partial truncate */
        printf("[*] ftruncate %s to %ld bytes...\n", fa, (long)trunc_to);
        if (truncate(fa, trunc_to) < 0) {
            perror("truncate E");
            ret = 1; goto cleanup_e;
        }

        if (verify_range(fa, 0, trunc_to, 'E') != 0) { ret = 1; goto cleanup_e; }
        printf("  -> Truncated OK, %ld bytes verified\n", (long)trunc_to);

        /* Now extend by writing past the truncation point */
        printf("[*] Writing 'X' at offset %ld to extend file...\n", (long)trunc_to);
        fd = open(fa, O_RDWR);
        if (fd < 0) { perror("open E rw"); ret = 1; goto cleanup_e; }

        /* Write from truncation point to fill out page 4 and add page 5 */
        long write_len = file_size - trunc_to;
        char *wbuf = malloc(write_len);
        memset(wbuf, 'X', write_len);
        ssize_t nw = pwrite(fd, wbuf, write_len, trunc_to);
        free(wbuf);
        if (nw != write_len) {
            perror("pwrite extend");
            close(fd); ret = 1; goto cleanup_e;
        }
        fsync(fd);
        close(fd);

        /* Verify file_a: first trunc_to bytes = 'E', rest = 'X' */
        if (verify_range(fa, 0, trunc_to, 'E') != 0) { ret = 1; goto cleanup_e; }
        if (verify_range(fa, trunc_to, write_len, 'X') != 0) { ret = 1; goto cleanup_e; }
        printf("  -> %s: first %ld bytes 'E', last %ld bytes 'X'\n",
               fa, (long)trunc_to, write_len);

        /* Verify file_b: COMPLETELY INTACT */
        if (verify_range(fb, 0, file_size, 'E') != 0) {
            fprintf(stderr, "  [FAIL] %s corrupted after partial truncate + extend!\n", fb);
            ret = 1; goto cleanup_e;
        }
        printf("  -> %s: all %ld bytes intact\n", fb, file_size);

        /* Delete both — tests nrpages after partial truncate + COW extension */
        unlink(fa);
        unlink(fb);
        usleep(500000);
        printf("  -> Scenario E: PASS\n\n");

cleanup_e:
        unlink("parttrunc_a5.dat");
        unlink("parttrunc_b5.dat");
        if (ret) return ret;
    }

    /* ================================================================== */
    if (ret == 0)
        printf("[PASS] All partial truncation scenarios passed\n");

    return ret;
}
