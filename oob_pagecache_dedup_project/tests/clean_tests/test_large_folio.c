/*
 * test_large_folio.c
 *
 * Force order > 0 folios via large sequential writes (XFS/ext4 with THP)
 * and verify dedup and COW work at non-order-0.
 *
 * Strategy:
 *   - Write two identical files with large sequential I/O (1 MB writes)
 *     so the kernel is likely to allocate large folios.
 *   - Queue both for dedup, wait for merge (may involve folio splitting).
 *   - Read both back and verify data integrity.
 *   - Write to file_a, verify file_b is untouched.
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

#define POSIX_FADV_DEDUP 8
#define PAGE_SIZE        4096
#define CHUNK_SIZE       (256 * PAGE_SIZE)  /* 1 MB write chunks */
#define FILE_SIZE_MB     4                  /* 4 MB per file */
#define TOTAL_CHUNKS     (FILE_SIZE_MB * 1024 * 1024 / CHUNK_SIZE)
#define FILE_A           "large_folio_a.dat"
#define FILE_B           "large_folio_b.dat"
#define SCANNER_WAIT     8

static int create_large_file(const char *path, char fill)
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

    int ret = posix_fadvise(fd, 0, 0, POSIX_FADV_DEDUP);
    if (ret != 0)
        fprintf(stderr, "  fadvise(%s): %s\n", path, strerror(ret));
    else
        printf("  [+] Queued: %s\n", path);

    close(fd);
    return 0;
}

static int verify_file_range(const char *path, char expected, long size)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); return 1; }

    char *buf = malloc(PAGE_SIZE);
    long remaining = size;
    long offset = 0;

    while (remaining > 0) {
        long to_read = remaining < PAGE_SIZE ? remaining : PAGE_SIZE;
        ssize_t nr = read(fd, buf, to_read);
        if (nr != to_read) {
            fprintf(stderr, "  [FAIL] %s: short read at offset %ld\n", path, offset);
            free(buf); close(fd); return 1;
        }
        for (long i = 0; i < to_read; i++) {
            if (buf[i] != expected) {
                fprintf(stderr, "  [FAIL] %s: byte %ld expected '%c' got 0x%02x\n",
                        path, offset + i, expected, (unsigned char)buf[i]);
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

int main(void)
{
    int ret = 0;
    long file_size = (long)FILE_SIZE_MB * 1024 * 1024;

    printf("TEST: Large Folio Dedup + COW\n");
    printf("[*] File size: %d MB, chunk size: %d KB\n",
           FILE_SIZE_MB, CHUNK_SIZE / 1024);

    /* --- 1. Create identical large files ------------------------------ */
    printf("[*] Creating %s...\n", FILE_A);
    if (create_large_file(FILE_A, 'L') < 0) return 1;
    printf("[*] Creating %s...\n", FILE_B);
    if (create_large_file(FILE_B, 'L') < 0) return 1;

    /* --- 2. Wait for scanner (may split + re-dedup) ------------------- */
    printf("[*] Sleeping %ds for scanner (split + dedup)...\n", SCANNER_WAIT);
    sleep(SCANNER_WAIT);

    /* --- 3. Verify both files intact ---------------------------------- */
    printf("[*] Verifying %s...\n", FILE_A);
    if (verify_file_range(FILE_A, 'L', file_size) != 0) { ret = 1; goto out; }
    printf("  -> FILE_A: OK\n");

    printf("[*] Verifying %s...\n", FILE_B);
    if (verify_file_range(FILE_B, 'L', file_size) != 0) { ret = 1; goto out; }
    printf("  -> FILE_B: OK\n");

    /* --- 4. COW: write to file_a, verify file_b untouched ------------- */
    printf("[*] Writing 'Q' to first page of %s...\n", FILE_A);
    int fd = open(FILE_A, O_RDWR);
    if (fd < 0) { perror("open file_a"); ret = 1; goto out; }
    char patch[PAGE_SIZE];
    memset(patch, 'Q', PAGE_SIZE);
    if (write(fd, patch, PAGE_SIZE) != PAGE_SIZE) {
        perror("write file_a"); close(fd); ret = 1; goto out;
    }
    close(fd);
    printf("  -> Write succeeded\n");

    /* Verify file_a: page 0 = 'Q', rest = 'L' */
    printf("[*] Verifying %s after write...\n", FILE_A);
    fd = open(FILE_A, O_RDONLY);
    if (fd < 0) { perror("open"); ret = 1; goto out; }
    char *check = malloc(PAGE_SIZE);

    /* page 0 */
    read(fd, check, PAGE_SIZE);
    for (int i = 0; i < PAGE_SIZE; i++) {
        if (check[i] != 'Q') {
            fprintf(stderr, "  [FAIL] file_a page0 byte %d\n", i);
            ret = 1; free(check); close(fd); goto out;
        }
    }
    /* rest */
    long remaining = file_size - PAGE_SIZE;
    while (remaining > 0) {
        long to_read = remaining < PAGE_SIZE ? remaining : PAGE_SIZE;
        read(fd, check, to_read);
        for (long i = 0; i < to_read; i++) {
            if (check[i] != 'L') {
                fprintf(stderr, "  [FAIL] file_a rest corrupted\n");
                ret = 1; free(check); close(fd); goto out;
            }
        }
        remaining -= to_read;
    }
    free(check);
    close(fd);
    printf("  -> FILE_A: COW correct\n");

    /* file_b should be pure 'L' */
    printf("[*] Verifying %s after file_a write...\n", FILE_B);
    if (verify_file_range(FILE_B, 'L', file_size) != 0) { ret = 1; goto out; }
    printf("  -> FILE_B: Untouched\n");

    if (ret == 0)
        printf("[PASS] Large folio test passed\n");
out:
    unlink(FILE_A);
    unlink(FILE_B);
    return ret;
}
