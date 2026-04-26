/*
 * profile_bench.c — Comprehensive benchmark helper for OOB page-cache dedup.
 *
 * Modes:
 *   --read      <file>                  Sequential read, report time_ns + throughput
 *   --write     <file>                  Sequential overwrite (4KB chunks), report time_ns
 *   --cow-write <file>                  Single 4KB pwrite at offset 0 (measures first-write COW)
 *   --dedup     <file1> <file2> ...     fadvise + poll sysfs until scanner done
 *   --dedup-wait <timeout_s>            Just poll files_queued until 0 (for pre-queued files)
 *   --meminfo                           Print Cached/MemFree/MemAvailable from /proc/meminfo
 *   --create    <file> <size_mb> <chr>  Create a file filled with <chr>
 *   --copy      <src> <dst>             Copy file
 *   --concurrent-rw <file> <threads>    Spawn N threads doing random 4KB reads+writes
 *
 * All numeric outputs are key: value for easy Python parsing.
 *
 * Build: gcc -O2 -pthread -o profile_bench profile_bench.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>

#define POSIX_FADV_DEDUP 8
#define SYSFS_ROOT       "/sys/kernel/oob_dedup/"
#define READ_CHUNK       (4 * 1024 * 1024)   /* 4 MB */
#define WRITE_CHUNK      4096                 /* 4 KB */
#define COW_CHUNK        4096                 /* 4 KB */

/* ─── Timing ──────────────────────────────────────────────── */

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* ─── Sysfs helpers ───────────────────────────────────────── */

static long read_sysfs_long(const char *name)
{
    char path[256], buf[64];
    snprintf(path, sizeof(path), SYSFS_ROOT "%s", name);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    return strtol(buf, NULL, 10);
}

/* ─── /proc/meminfo parser ────────────────────────────────── */

static long parse_meminfo_kb(const char *key)
{
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) return -1;
    char line[256];
    size_t klen = strlen(key);
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, key, klen) == 0 && line[klen] == ':') {
            long val = strtol(line + klen + 1, NULL, 10);
            fclose(fp);
            return val;
        }
    }
    fclose(fp);
    return -1;
}

/* ─── Mode: meminfo ───────────────────────────────────────── */

static void do_meminfo(void)
{
    printf("cached_kb: %ld\n",       parse_meminfo_kb("Cached"));
    printf("mem_free_kb: %ld\n",     parse_meminfo_kb("MemFree"));
    printf("mem_available_kb: %ld\n", parse_meminfo_kb("MemAvailable"));
    printf("buffers_kb: %ld\n",      parse_meminfo_kb("Buffers"));
    printf("active_file_kb: %ld\n",  parse_meminfo_kb("Active(file)"));
    printf("inactive_file_kb: %ld\n",parse_meminfo_kb("Inactive(file)"));
}

/* ─── Mode: sysfs snapshot ────────────────────────────────── */

static void do_sysfs_snapshot(void)
{
    printf("pages_scanned: %ld\n",    read_sysfs_long("pages_scanned"));
    printf("pages_deduped: %ld\n",    read_sysfs_long("pages_deduped"));
    printf("files_queued: %ld\n",     read_sysfs_long("files_queued"));
    printf("folios_split: %ld\n",     read_sysfs_long("folios_split"));
    printf("sleep_millisecs: %ld\n",  read_sysfs_long("sleep_millisecs"));
    printf("pages_to_scan: %ld\n",    read_sysfs_long("pages_to_scan"));
}

/* ─── Mode: create file ───────────────────────────────────── */

static void do_create(const char *path, int size_mb, char fill)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("create open"); exit(1); }

    size_t total = (size_t)size_mb * 1024 * 1024;
    size_t chunk = 1024 * 1024; /* 1 MB at a time */
    char *buf = malloc(chunk);
    if (!buf) { perror("malloc"); exit(1); }
    memset(buf, fill, chunk);

    size_t written = 0;
    while (written < total) {
        size_t n = (total - written < chunk) ? total - written : chunk;
        ssize_t w = write(fd, buf, n);
        if (w < 0) { perror("write"); exit(1); }
        written += (size_t)w;
    }
    fsync(fd);
    close(fd);
    free(buf);
    printf("created: %s\n", path);
    printf("size_bytes: %zu\n", total);
}

/* ─── Mode: copy file ─────────────────────────────────────── */

static void do_copy(const char *src, const char *dst)
{
    int fds = open(src, O_RDONLY);
    int fdd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fds < 0 || fdd < 0) { perror("copy open"); exit(1); }

    char buf[1024 * 1024];
    ssize_t n;
    while ((n = read(fds, buf, sizeof(buf))) > 0) {
        ssize_t w = write(fdd, buf, (size_t)n);
        if (w != n) { perror("copy write"); exit(1); }
    }
    fsync(fdd);
    close(fds);
    close(fdd);
    printf("copied: %s -> %s\n", src, dst);
}

/* ─── Mode: read ──────────────────────────────────────────── */

static void do_read(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("read open"); exit(1); }

    struct stat st;
    fstat(fd, &st);

    void *buf = malloc(READ_CHUNK);
    if (!buf) { perror("malloc"); exit(1); }

    uint64_t t0 = now_ns();
    size_t total = 0;
    ssize_t n;
    while ((n = read(fd, buf, READ_CHUNK)) > 0)
        total += (size_t)n;
    uint64_t elapsed = now_ns() - t0;

    free(buf);
    close(fd);

    double mb = (double)total / (1024.0 * 1024.0);
    double sec = (double)elapsed / 1e9;
    printf("read_time_ns: %llu\n", (unsigned long long)elapsed);
    printf("read_bytes: %zu\n", total);
    printf("read_throughput_mbps: %.2f\n", sec > 0 ? mb / sec : 0);
}

/* ─── Mode: write (full overwrite) ────────────────────────── */

static void do_write(const char *path)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) { perror("write open"); exit(1); }

    struct stat st;
    fstat(fd, &st);

    char *buf = malloc(WRITE_CHUNK);
    if (!buf) { perror("malloc"); exit(1); }
    memset(buf, 'W', WRITE_CHUNK);

    uint64_t t0 = now_ns();
    off_t off = 0;
    while (off < st.st_size) {
        size_t n = (size_t)(st.st_size - off);
        if (n > WRITE_CHUNK) n = WRITE_CHUNK;
        ssize_t w = pwrite(fd, buf, n, off);
        if (w < 0) { perror("pwrite"); exit(1); }
        off += w;
    }
    fsync(fd);
    uint64_t elapsed = now_ns() - t0;

    free(buf);
    close(fd);

    double mb = (double)st.st_size / (1024.0 * 1024.0);
    double sec = (double)elapsed / 1e9;
    printf("write_time_ns: %llu\n", (unsigned long long)elapsed);
    printf("write_bytes: %lld\n", (long long)st.st_size);
    printf("write_throughput_mbps: %.2f\n", sec > 0 ? mb / sec : 0);
}

/* ─── Mode: cow-write (single 4KB write at offset 0) ──────── */

static void do_cow_write(const char *path)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) { perror("cow open"); exit(1); }

    char buf[COW_CHUNK];
    memset(buf, 'C', COW_CHUNK);

    uint64_t t0 = now_ns();
    ssize_t w = pwrite(fd, buf, COW_CHUNK, 0);
    fsync(fd);
    uint64_t elapsed = now_ns() - t0;

    close(fd);
    if (w < 0) { perror("cow pwrite"); exit(1); }

    printf("cow_write_time_ns: %llu\n", (unsigned long long)elapsed);
    printf("cow_write_bytes: %zd\n", (size_t)w);
}

/* ─── Mode: dedup (fadvise + poll) ────────────────────────── */

static void do_dedup(int nfiles, char **paths)
{
    long deduped_before = read_sysfs_long("pages_deduped");
    long scanned_before = read_sysfs_long("pages_scanned");

    int *fds = malloc(sizeof(int) * (size_t)nfiles);
    for (int i = 0; i < nfiles; i++) {
        fds[i] = open(paths[i], O_RDONLY);
        if (fds[i] < 0) { perror("dedup open"); exit(1); }
        /* warm page cache */
        char tmp[4096];
        while (read(fds[i], tmp, sizeof(tmp)) > 0) {}
        lseek(fds[i], 0, SEEK_SET);
    }

    uint64_t t0 = now_ns();

    for (int i = 0; i < nfiles; i++)
        posix_fadvise(fds[i], 0, 0, POSIX_FADV_DEDUP);

    /* poll files_queued until 0 */
    int polls = 0;
    while (1) {
        long q = read_sysfs_long("files_queued");
        if (q == 0) break;
        if (q < 0) { fprintf(stderr, "Cannot read files_queued\n"); exit(1); }
        usleep(500);
        polls++;
        if (polls > 600000) { /* 5 min timeout */
            fprintf(stderr, "Dedup timeout!\n");
            break;
        }
    }

    uint64_t elapsed = now_ns() - t0;

    for (int i = 0; i < nfiles; i++)
        close(fds[i]);
    free(fds);

    long deduped_after = read_sysfs_long("pages_deduped");
    long scanned_after = read_sysfs_long("pages_scanned");

    printf("dedup_time_ns: %llu\n",     (unsigned long long)elapsed);
    printf("dedup_files: %d\n",          nfiles);
    printf("pages_deduped_delta: %ld\n", deduped_after - deduped_before);
    printf("pages_scanned_delta: %ld\n", scanned_after - scanned_before);
    printf("dedup_polls: %d\n",          polls);
}

/* ─── Mode: dedup-wait (just poll, files already queued) ──── */

static void do_dedup_wait(int timeout_s)
{
    uint64_t t0 = now_ns();
    int elapsed_s = 0;
    while (elapsed_s < timeout_s) {
        long q = read_sysfs_long("files_queued");
        if (q == 0) break;
        usleep(500);
        elapsed_s = (int)((now_ns() - t0) / 1000000000ULL);
    }
    uint64_t elapsed = now_ns() - t0;
    printf("wait_time_ns: %llu\n", (unsigned long long)elapsed);
    printf("files_queued_final: %ld\n", read_sysfs_long("files_queued"));
}

/* ─── Mode: concurrent-rw ─────────────────────────────────── */

struct crw_args {
    const char *path;
    int thread_id;
    int iterations;
    uint64_t read_ns;
    uint64_t write_ns;
};

static void *crw_worker(void *arg)
{
    struct crw_args *a = (struct crw_args *)arg;
    char buf[4096];
    unsigned int seed = (unsigned int)(a->thread_id * 1234 + 5678);

    int fd = open(a->path, O_RDWR);
    if (fd < 0) { perror("crw open"); return NULL; }

    struct stat st;
    fstat(fd, &st);
    long npages = st.st_size / 4096;
    if (npages <= 0) npages = 1;

    uint64_t rns = 0, wns = 0;

    for (int i = 0; i < a->iterations; i++) {
        off_t off = (off_t)((long)rand_r(&seed) % npages) * 4096;

        /* timed read */
        uint64_t t0 = now_ns();
        pread(fd, buf, 4096, off);
        rns += now_ns() - t0;

        /* timed write */
        memset(buf, 'T', 4096);
        t0 = now_ns();
        pwrite(fd, buf, 4096, off);
        wns += now_ns() - t0;
    }

    close(fd);
    a->read_ns = rns;
    a->write_ns = wns;
    return NULL;
}

static void do_concurrent_rw(const char *path, int nthreads, int iters_per_thread)
{
    pthread_t *tids = malloc(sizeof(pthread_t) * (size_t)nthreads);
    struct crw_args *args = malloc(sizeof(struct crw_args) * (size_t)nthreads);

    uint64_t t0 = now_ns();

    for (int i = 0; i < nthreads; i++) {
        args[i].path = path;
        args[i].thread_id = i;
        args[i].iterations = iters_per_thread;
        args[i].read_ns = 0;
        args[i].write_ns = 0;
        pthread_create(&tids[i], NULL, crw_worker, &args[i]);
    }

    uint64_t total_read_ns = 0, total_write_ns = 0;
    for (int i = 0; i < nthreads; i++) {
        pthread_join(tids[i], NULL);
        total_read_ns += args[i].read_ns;
        total_write_ns += args[i].write_ns;
    }

    uint64_t wall = now_ns() - t0;
    int total_ops = nthreads * iters_per_thread;

    printf("crw_wall_ns: %llu\n",       (unsigned long long)wall);
    printf("crw_threads: %d\n",          nthreads);
    printf("crw_ops_per_thread: %d\n",   iters_per_thread);
    printf("crw_total_ops: %d\n",        total_ops);
    printf("crw_avg_read_ns: %llu\n",    (unsigned long long)(total_read_ns / (unsigned)total_ops));
    printf("crw_avg_write_ns: %llu\n",   (unsigned long long)(total_write_ns / (unsigned)total_ops));

    free(tids);
    free(args);
}

/* ─── Main ────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    if (argc < 2) goto usage;

    if (strcmp(argv[1], "--read") == 0 && argc == 3)
        do_read(argv[2]);
    else if (strcmp(argv[1], "--write") == 0 && argc == 3)
        do_write(argv[2]);
    else if (strcmp(argv[1], "--cow-write") == 0 && argc == 3)
        do_cow_write(argv[2]);
    else if (strcmp(argv[1], "--dedup") == 0 && argc >= 3)
        do_dedup(argc - 2, argv + 2);
    else if (strcmp(argv[1], "--dedup-wait") == 0 && argc == 3)
        do_dedup_wait(atoi(argv[2]));
    else if (strcmp(argv[1], "--meminfo") == 0)
        do_meminfo();
    else if (strcmp(argv[1], "--sysfs") == 0)
        do_sysfs_snapshot();
    else if (strcmp(argv[1], "--create") == 0 && argc == 5)
        do_create(argv[2], atoi(argv[3]), argv[4][0]);
    else if (strcmp(argv[1], "--copy") == 0 && argc == 4)
        do_copy(argv[2], argv[3]);
    else if (strcmp(argv[1], "--concurrent-rw") == 0 && argc >= 4) {
        int thr = atoi(argv[3]);
        int iters = (argc >= 5) ? atoi(argv[4]) : 1000;
        do_concurrent_rw(argv[2], thr, iters);
    }
    else goto usage;

    return 0;

usage:
    fprintf(stderr,
        "Usage:\n"
        "  %s --read <file>\n"
        "  %s --write <file>\n"
        "  %s --cow-write <file>\n"
        "  %s --dedup <file1> [file2 ...]\n"
        "  %s --dedup-wait <timeout_s>\n"
        "  %s --meminfo\n"
        "  %s --sysfs\n"
        "  %s --create <file> <size_mb> <fill_char>\n"
        "  %s --copy <src> <dst>\n"
        "  %s --concurrent-rw <file> <threads> [iters_per_thread]\n",
        argv[0], argv[0], argv[0], argv[0], argv[0],
        argv[0], argv[0], argv[0], argv[0], argv[0]);
    return 1;
}
