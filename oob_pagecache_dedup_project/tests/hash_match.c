#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define POSIX_FADV_DEDUP 8

int main(void) {
    const char *filename = "dedup_test_file.txt";
    int fd;
    long page_size = 4096;
    char *block_A = malloc(page_size);
    char *block_B = malloc(page_size);
    if (!block_A || !block_B) {
        perror("Memory allocation failed");
        return 1;
    }
    memset(block_A, 'A', page_size);
    memset(block_B, 'B', page_size);

    fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("Error opening file");
        free(block_A);
        free(block_B);
        return 1;
    }
    
    /* Write Page 0: Block A */
    if (write(fd, block_A, page_size) != page_size) perror("Write error");
    
    /* Write Page 1: Block B */
    if (write(fd, block_B, page_size) != page_size) perror("Write error");
    
    /* Write Page 2: Block A */
    if (write(fd, block_A, page_size) != page_size) perror("Write error");

    fsync(fd);
    printf("Wrote 3 pages (A, B, A) to page cache.\n");

    printf("Sending POSIX_FADV_DEDUP (8) to kernel for file: %s\n", filename);
    int ret = posix_fadvise(fd, 0, 0, POSIX_FADV_DEDUP);

    if (ret != 0) {
        if (ret == EINVAL) {
            fprintf(stderr, "Error: POSIX_FADV_DEDUP (%d) not recognised.\n", POSIX_FADV_DEDUP);
        } else {
            fprintf(stderr, "fadvise failed: %s\n", strerror(ret));
        }
    } else {
        printf("Success! Mapping %p (via fd %d) is now in the OOB Dedup queue.\n", (void*)&fd, fd);
    }

    close(fd);
    free(block_A);
    free(block_B);
    
    return 0;
}