#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#define POSIX_FADV_DEDUP 8

int create_and_queue(const char *filename, char **blocks, int num_blocks, long page_size) {
    int fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("Error opening file");
        return -1;
    }

    for (int i = 0; i < num_blocks; i++) {
        if (write(fd, blocks[i], page_size) != page_size) {
            perror("Write error");
            close(fd);
            return -1;
        }
    }

    fsync(fd);

    int ret = posix_fadvise(fd, 0, 0, POSIX_FADV_DEDUP);
    if (ret != 0) {
        fprintf(stderr, "fadvise failed on %s: %s\n", filename, strerror(ret));
    } else {
        printf(" [+] Queued: %s\n", filename);
    }

    close(fd);
    return 0;
}