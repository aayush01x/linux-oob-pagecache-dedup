#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include "common.h"

int main() {
    long page_size = 4096;
    int num_pages = 5120; /* 1 MB per file */
    
    printf("--- DEDUP WORKLOAD GENERATOR ---\n");
    
    /* 1. Setup Test Data (4 Identical 1MB Files) */
    char *pages[num_pages];
    for (int i = 0; i < num_pages; i++) {
        pages[i] = malloc(page_size);
        memset(pages[i], 'A', page_size); /* All pages identical */
    }

    /* 2. Create and Queue Files */
    printf("[*] Creating and queuing 4 identical 1MB files...\n");
    create_and_queue("stat_file1.dat", pages, num_pages, page_size);
    create_and_queue("stat_file2.dat", pages, num_pages, page_size);
    create_and_queue("stat_file3.dat", pages, num_pages, page_size);
    create_and_queue("stat_file4.dat", pages, num_pages, page_size);

    /* 3. Wait for the daemon to process */
    int wait_seconds = 10;
    printf("[*] Workload queued. Sleeping for %d seconds...\n", wait_seconds);
    printf("[*] -> Go check your sysfs stats now! <-\n");
    
    sleep(wait_seconds);

    /* 4. Cleanup */
    printf("[*] Waking up. Unlinking files and freeing memory...\n");
    for (int i = 0; i < num_pages; i++) {
        free(pages[i]);
    }
    
    /* Note: Unlinking will trigger your evict_inode cleanup logic */
    unlink("stat_file1.dat"); 
    unlink("stat_file2.dat");
    unlink("stat_file3.dat"); 
    unlink("stat_file4.dat");

    printf("[*] Exiting cleanly.\n");
    return 0;
}
