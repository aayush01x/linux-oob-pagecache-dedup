#define _FILE_OFFSET_BITS 64
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define FILENAME "dedup_test_2gb.bin"
#define BLOCK_SIZE (4096) // 1MB buffer
#define TOTAL_BLOCKS 2048        // 2048 * 1MB = 2GB

int main() {
    int fd;
    char *buf;

    buf = malloc(BLOCK_SIZE);
    if (!buf) {
        perror("Malloc failed");
        return 1;
    }
    memset(buf, 'A', BLOCK_SIZE);

    printf("[Writer] Creating %s (2GB)...\n", FILENAME);
    fd = open(FILENAME, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("Open failed");
        return 1;
    }

    for (int i = 0; i < TOTAL_BLOCKS; i++) {
        if (write(fd, buf, BLOCK_SIZE) != BLOCK_SIZE) {
            perror("Write failed");
            close(fd);
            return 1;
        }
        if ((i + 1) % 512 == 0) printf("  ... %d MB written\n", i + 1);
    }

    printf("[Writer] Syncing to disk...\n");
    fsync(fd);
    
    printf("[Writer] Done. Exiting.\n");
    close(fd);
    free(buf);
    return 0;
}
