/*
 * test_08_cascade_unlink.c
 *
 * CASCADE UNLINK CORRECTNESS TEST — 5 files sharing the same folios
 *
 * This exercises the rmap_count dissolve cascade: when N files share a
 * folio and you delete them one-by-one, each deletion must:
 *   - Remove exactly one rmap entry from the folio's rmap_list.
 *   - Decrement nrpages by folio_nr_pages ONCE per file.
 *   - When rmap_count drops to 1, dissolve the dedup info and restore
 *     folio->mapping to the surviving file's mapping.
 *   - When the last file is deleted, folio->mapping = NULL and the
 *     folio is freed.
 *   - clear_inode() must see nrpages == 0 for each deleted inode.
 *
 * After each deletion, the surviving files are read back to verify
 * data integrity. This catches off-by-one rmap removals, double
 * nrpages decrements, and premature folio free.
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
#define NUM_PAGES     4
#define NUM_FILES     5
#define SCANNER_WAIT  8

static const char *file_paths[NUM_FILES] = {
    "cascade_a.dat",
    "cascade_b.dat",
    "cascade_c.dat",
    "cascade_d.dat",
    "cascade_e.dat",
};

static int verify_file_content(const char *path, long size, char fill)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "  [FAIL] Cannot open %s: %s\n", path, strerror(errno));
        return 1;
    }
    char *buf = malloc(size);
    if (!buf) { close(fd); return 1; }

    ssize_t nr = read(fd, buf, size);
    close(fd);

    if (nr != size) {
        fprintf(stderr, "  [FAIL] %s: short read (%zd vs %ld)\n", path, nr, size);
        free(buf);
        return 1;
    }
    for (long i = 0; i < size; i++) {
        if (buf[i] != fill) {
            fprintf(stderr, "  [FAIL] %s byte %ld: expected 0x%02x, got 0x%02x\n",
                    path, i, (unsigned char)fill, (unsigned char)buf[i]);
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
    long file_size = (long)PAGE_SIZE * NUM_PAGES;

    printf("TEST: Cascade Unlink (5-way shared folio, serial deletion)\n");

    /* --- 1. Create 5 identical files ---------------------------------- */
    char *blk = malloc(PAGE_SIZE);
    if (!blk) { perror("malloc"); return 1; }
    memset(blk, 'C', PAGE_SIZE);

    char *pages[NUM_PAGES];
    for (int i = 0; i < NUM_PAGES; i++)
        pages[i] = blk;

    printf("[*] Creating %d identical %d-page files...\n", NUM_FILES, NUM_PAGES);
    for (int f = 0; f < NUM_FILES; f++) {
        if (create_and_queue(file_paths[f], pages, NUM_PAGES, PAGE_SIZE) < 0) {
            ret = 1;
            goto out;
        }
    }

    /* --- 2. Wait for dedup -------------------------------------------- */
    printf("[*] Sleeping %ds for scanner to merge all %d files...\n",
           SCANNER_WAIT, NUM_FILES);
    sleep(SCANNER_WAIT);

    /* --- 3. Verify all files before deletion -------------------------- */
    printf("[*] Pre-deletion verification...\n");
    for (int f = 0; f < NUM_FILES; f++) {
        if (verify_file_content(file_paths[f], file_size, 'C') != 0) {
            ret = 1;
            goto out;
        }
        printf("  -> %s: OK\n", file_paths[f]);
    }

    /* --- 4. Delete files one by one, verify survivors each time -------- */
    for (int del = 0; del < NUM_FILES; del++) {
        printf("\n[*] Deleting %s (file %d/%d)...\n",
               file_paths[del], del + 1, NUM_FILES);

        if (unlink(file_paths[del]) != 0) {
            fprintf(stderr, "  [FAIL] unlink %s: %s\n",
                    file_paths[del], strerror(errno));
            ret = 1;
            goto out;
        }
        /* Let inode eviction run */
        usleep(300000);
        printf("  -> Deleted OK\n");

        /* Verify all surviving files */
        int survivors = 0;
        for (int f = del + 1; f < NUM_FILES; f++) {
            if (verify_file_content(file_paths[f], file_size, 'C') != 0) {
                fprintf(stderr, "  [FAIL] Survivor %s corrupted after "
                        "deleting %s\n", file_paths[f], file_paths[del]);
                ret = 1;
                goto out;
            }
            survivors++;
        }
        if (survivors > 0)
            printf("  -> %d survivor(s) verified OK\n", survivors);
    }

    if (ret == 0)
        printf("\n[PASS] Cascade unlink test passed\n");

out:
    free(blk);
    for (int f = 0; f < NUM_FILES; f++)
        unlink(file_paths[f]);
    return ret;
}
