#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#define POSIX_FADV_DEDUP 8
#define SYSFS_FILES_QUEUED "/sys/kernel/oob_dedup/files_queued"
#define READ_CHUNK_SIZE (1024 * 1024 * 4) // 4MB reads
#define WRITE_CHUNK_SIZE (4096) // 4KB writes

uint64_t get_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int read_files_queued() {
    char buf[32];
    int fd = open(SYSFS_FILES_QUEUED, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n > 0) {
        buf[n] = '\0';
        return atoi(buf);
    }
    return -1;
}

void do_dedup(int argc, char **argv, int start_idx) {
    int num_files = argc - start_idx;
    int *fds = malloc(sizeof(int) * num_files);
    
    // Open all files
    for (int i = 0; i < num_files; i++) {
        fds[i] = open(argv[start_idx + i], O_RDONLY);
        if (fds[i] < 0) {
            perror("open");
            exit(1);
        }
    }

    uint64_t start = get_time_ns();

    // Queue for dedup
    for (int i = 0; i < num_files; i++) {
        posix_fadvise(fds[i], 0, 0, POSIX_FADV_DEDUP);
    }

    // Poll until files_queued == 0
    while (1) {
        int queued = read_files_queued();
        if (queued == 0) {
            break;
        } else if (queued < 0) {
            fprintf(stderr, "Failed to read files_queued, is oob_dedup loaded?\n");
            exit(1);
        }
        // Micro-sleep to avoid 100% CPU lockup while polling
        usleep(100); 
    }

    uint64_t end = get_time_ns();
    
    for (int i = 0; i < num_files; i++) {
        close(fds[i]);
    }
    free(fds);

    printf("DEDUP_TIME_NS: %llu\n", (unsigned long long)(end - start));
}

void do_read(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open for read");
        exit(1);
    }

    void *buf = malloc(READ_CHUNK_SIZE);
    if (!buf) {
        perror("malloc");
        exit(1);
    }

    uint64_t start = get_time_ns();
    
    while (1) {
        ssize_t n = read(fd, buf, READ_CHUNK_SIZE);
        if (n < 0) {
            perror("read");
            exit(1);
        }
        if (n == 0) break; // EOF
    }

    uint64_t end = get_time_ns();

    free(buf);
    close(fd);

    printf("READ_TIME_NS: %llu\n", (unsigned long long)(end - start));
}

void do_write(const char *filename) {
    // We open with O_WRONLY to do partial overwrites
    int fd = open(filename, O_WRONLY);
    if (fd < 0) {
        perror("open for write");
        exit(1);
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        exit(1);
    }

    void *buf = malloc(WRITE_CHUNK_SIZE);
    if (!buf) {
        perror("malloc");
        exit(1);
    }
    memset(buf, 'W', WRITE_CHUNK_SIZE);

    uint64_t start = get_time_ns();

    // Overwrite the file in WRITE_CHUNK_SIZE chunks
    // To trigger CoW effectively, we can just rewrite the whole file 
    // or parts of it. We'll rewrite the whole file sequentially.
    off_t offset = 0;
    while (offset < st.st_size) {
        ssize_t to_write = st.st_size - offset;
        if (to_write > WRITE_CHUNK_SIZE) to_write = WRITE_CHUNK_SIZE;
        
        ssize_t n = pwrite(fd, buf, to_write, offset);
        if (n < 0) {
            perror("pwrite");
            exit(1);
        }
        offset += n;
    }

    // Sync to ensure it's written and CoW is fully accounted for
    fsync(fd);

    uint64_t end = get_time_ns();

    free(buf);
    close(fd);

    printf("WRITE_TIME_NS: %llu\n", (unsigned long long)(end - start));
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s --dedup <file1> ... | --read <file> | --write <file>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--dedup") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Missing files for --dedup\n");
            return 1;
        }
        do_dedup(argc, argv, 2);
    } else if (strcmp(argv[1], "--read") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s --read <file>\n", argv[0]);
            return 1;
        }
        do_read(argv[2]);
    } else if (strcmp(argv[1], "--write") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s --write <file>\n", argv[0]);
            return 1;
        }
        do_write(argv[2]);
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
