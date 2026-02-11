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
    fd = open(filename, O_RDWR | O_CREAT, 0644);
    if (fd < 0) {
        perror("Error opening file");
        return 1;
    }
    if (write(fd, "Hello Kernel World", 18) != 18) {
        perror("Error writing to file");
        close(fd);
        return 1;
    }
    
    fsync(fd);

    printf("Sending POSIX_FADV_DEDUP (8) to kernel for file: %s\n", filename);
    int ret = posix_fadvise(fd, 0, 0, POSIX_FADV_DEDUP);

    if (ret != 0) {
        fprintf(stderr, "fadvise failed: %s\n", strerror(ret));
    } else {
        printf("Success! System call returned 0.\n");
    }

    close(fd);
    return 0;
}
