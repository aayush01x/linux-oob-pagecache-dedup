#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#include <unistd.h>

#include <fcntl.h>

#include "common.h"



int main() {

    long page_size = 4096;

    char *blk = malloc(page_size);

    memset(blk, 'D', page_size); 



    printf("TEST: Dedup followed by Deletion\n");



    char *pages[] = {blk};



    // 1. Create identical files

    printf("[*] Creating identical files to trigger dedup...\n");

    create_and_queue("file_to_del_1.txt", pages, 1, page_size);

    create_and_queue("file_to_del_2.txt", pages, 1, page_size);



    // 2. Wait for OOB thread

    printf("[*] Sleeping 2s for background merge...\n");

    sleep(5); 


	getchar();
    // 3. Delete files (Triggers your modified page_cache_delete)

    printf("[*] Deleting file_to_del_1.txt...\n");

    if (remove("file_to_del_1.txt") != 0) {

        perror("remove 1 failed");

        return 1;

    }


	getchar();
    printf("[*] Deleting file_to_del_2.txt...\n");

    if (remove("file_to_del_2.txt") != 0) {

        perror("remove 2 failed");

        return 1;

    }



    printf("SUCCESS: Files deleted. Check dmesg for OOB disconnect logs.\n");



    free(blk);

    return 0;

}
