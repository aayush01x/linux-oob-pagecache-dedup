/*
 * test_cow_during_truncate.c
 *
 * COW WRITE DURING ACTIVE TRUNCATION — targets oob_folio_break_dedup bugs
 *
 * Bug 3 & 4 in oob_folio_break_dedup:
 *   - info->lock released before xas_unlock_irq, then info is freed (UAF).
 *   - folio_unlock(old_folio) and folio_put(old_folio) called AFTER xas_unlock,
 *     allowing another CPU to free old_folio first (UAF).
 *
 * To trigger these:
 *   1. Create 2 files (A, B) with 64 identical pages. Queue for dedup.
 *   2. Wait for full merge.
 *   3. Fork a child that does rapid pwrite() to EVERY page of file A
 *      (triggers oob_folio_break_dedup 64 times in quick succession).
 *   4. Parent simultaneously truncates file B page by page from the end.
 *   5. The truncation reduces rmap_count while break_dedup is running,
 *      creating a race window where dissolve + free can happen under
 *      break_dedup's feet.
 *
 * If the unlock ordering bug is hit, the kernel oopses or hangs.
 * If the folio UAF is hit, we get a kernel NULL deref or corruption.
 *
 * Exit: 0 = PASS, 1 = FAIL
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include "common.h"

#define PAGE_SIZE       4096
#define NUM_PAGES       64
#define FILE_A          "cowtrunc_a.dat"
#define FILE_B          "cowtrunc_b.dat"
#define SCANNER_WAIT    10
#define COW_ROUNDS      3

int main(void)
{
    int ret = 0;
    long file_size = (long)PAGE_SIZE * NUM_PAGES;

    printf("TEST: COW During Active Truncation (targets break_dedup races)\n");

    /* Create identical files */
    char *blk = malloc(PAGE_SIZE);
    memset(blk, 'H', PAGE_SIZE);
    char *pages[NUM_PAGES];
    for (int i = 0; i < NUM_PAGES; i++) pages[i] = blk;

    printf("[*] Creating 2 identical %d-page files...\n", NUM_PAGES);
    if (create_and_queue(FILE_A, pages, NUM_PAGES, PAGE_SIZE) < 0 ||
        create_and_queue(FILE_B, pages, NUM_PAGES, PAGE_SIZE) < 0) {
        free(blk); return 1;
    }
    free(blk);

    printf("[*] Sleeping %ds for dedup...\n", SCANNER_WAIT);
    sleep(SCANNER_WAIT);

    printf("[*] Starting concurrent COW + truncation...\n");

    /* Child: rapid COW writes to every page of file A */
    pid_t child = fork();
    if (child == 0) {
        char wbuf[PAGE_SIZE];
        for (int round = 0; round < COW_ROUNDS; round++) {
            int fd = open(FILE_A, O_RDWR);
            if (fd < 0) _exit(1);
            for (int pg = 0; pg < NUM_PAGES; pg++) {
                memset(wbuf, 'A' + (round % 26), PAGE_SIZE);
                if (pwrite(fd, wbuf, PAGE_SIZE, (off_t)pg * PAGE_SIZE) != PAGE_SIZE) {
                    /* Might get errors if truncation is happening on B
                     * and dissolve changes folio state — that's expected */
                }
            }
            fsync(fd);
            close(fd);
        }
        _exit(0);
    }

    /* Parent: truncate file B page by page from the end */
    for (int pg = NUM_PAGES - 1; pg >= 0; pg--) {
        if (truncate(FILE_B, (off_t)pg * PAGE_SIZE) < 0) {
            /* Truncation errors are not expected but handle gracefully */
            if (errno != ENOENT) {
                perror("truncate B");
            }
            break;
        }
        /* Tiny sleep to interleave with child's writes */
        usleep(1000);
    }

    /* Delete file B */
    unlink(FILE_B);

    /* Wait for child */
    int status;
    waitpid(child, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "  [WARN] COW writer child had errors (may be expected)\n");
    } else {
        printf("  -> COW writer completed OK\n");
    }

    /* Verify file A is readable */
    printf("[*] Verifying file A is readable...\n");
    int fd = open(FILE_A, O_RDONLY);
    if (fd >= 0) {
        char *rbuf = malloc(file_size);
        ssize_t nr = read(fd, rbuf, file_size);
        close(fd);
        if (nr == file_size) {
            printf("  -> File A: %zd bytes read OK\n", nr);
        } else {
            printf("  -> File A: read %zd bytes (file may have been modified)\n", nr);
        }
        free(rbuf);
    } else {
        fprintf(stderr, "  [FAIL] Cannot open file A\n");
        ret = 1;
    }

    /* Delete file A */
    unlink(FILE_A);
    usleep(500000);

    /* If kernel didn't panic/oops, we passed */
    if (ret == 0)
        printf("[PASS] COW during truncation test passed\n");

    return ret;
}
