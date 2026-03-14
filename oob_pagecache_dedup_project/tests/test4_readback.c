// test4_readback.c
// Verifies that after dedup, file content is still correct on re-read.

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#define NUM_BLOCKS 4
#define TEST_FILE  "test4_readback.txt"

#include "common.h"

int main(void)
{
    printf("TEST 4: Readback Verification After Dedup\n");

    long page_size = sysconf(_SC_PAGESIZE);

    // blocks 0 and 2 are identical (0xAA)
    // blocks 1 and 3 are identical (0xBB) 
    char *blocks[NUM_BLOCKS];
    for (int i = 0; i < NUM_BLOCKS; i++) {
        blocks[i] = malloc(page_size);
        if (!blocks[i]) {
            perror("malloc");
            return 1;
        }
        memset(blocks[i], (i % 2 == 0) ? 0xAA : 0xBB, page_size);
    }

    if (create_and_queue(TEST_FILE, blocks, NUM_BLOCKS, page_size) < 0) {
        return 1;
    }

    // --- wait for kthread to scan and remove dup folio ---
    usleep(200000);


    int fd = open(TEST_FILE, O_RDONLY);
    if (fd < 0) {
        perror("open for readback");
        return 1;
    }

    int failed = 0;
    for (int i = 0; i < NUM_BLOCKS; i++) {
        char *readback = malloc(page_size);
        if (!readback) {
            perror("malloc readback");
            close(fd);
            return 1;
        }

        ssize_t n = read(fd, readback, page_size);
        if (n != page_size) {
            fprintf(stderr, " [FAIL] Short read on block %d: got %zd\n", i, n);
            free(readback);
            failed = 1;
            continue;
        }

        if (memcmp(blocks[i], readback, page_size) != 0) {
            fprintf(stderr, " [FAIL] Block %d content mismatch after dedup!\n", i);
            failed = 1;
        } else {
            printf(" [+] Block %d readback OK\n", i);
        }

        free(readback);
    }
    close(fd);

    if (!failed)
        printf(" [PASS] All blocks verified correct after dedup\n");

    for (int i = 0; i < NUM_BLOCKS; i++)
        free(blocks[i]);
    unlink(TEST_FILE);

    return failed;
}