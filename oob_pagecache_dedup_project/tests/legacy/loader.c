#define _FILE_OFFSET_BITS 64
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define FILENAME "dedup_test_2gb.bin"
#define POSIX_FADV_DEDUP 8
#define BLOCK_SIZE (4096)

int main() {
    int fd;
    char *read_buf;
    ssize_t bytes_read;
    long total_read = 0;

    fd = open(FILENAME, O_RDONLY);
    if (fd < 0) {
        perror("Could not open file. Did you run the writer?");
        return 1;
    }

    /* 1. Set the custom flag for the OOB scanner */
    printf("[Loader] Setting POSIX_FADV_DEDUP flag...\n");
    if (posix_fadvise(fd, 0, 0, POSIX_FADV_DEDUP) != 0) {
        perror("fadvise failed");
        close(fd);
        return 1;
    }

    /* 2. Read the entire file to load it into the Page Cache */
    printf("[Loader] Reading 2GB into Page Cache...\n");
    read_buf = malloc(BLOCK_SIZE);
    
    while ((bytes_read = read(fd, read_buf, BLOCK_SIZE)) > 0) {
        total_read += bytes_read;
        if (total_read % (512 * BLOCK_SIZE) == 0) {
            printf("  ... %ld MB loaded into RAM\n", total_read / (4096));
        }
    }

    printf("[Loader] 2GB loaded. The OOB scanner should now see 'Uptodate' folios.\n");
    printf("[Loader] Keeping file open for 20s to allow scanning... (Check dmesg)\n");
    
    sleep(20); 

    printf("[Loader] Closing file and exiting.\n");
    close(fd);
    free(read_buf);
    return 0;
}
