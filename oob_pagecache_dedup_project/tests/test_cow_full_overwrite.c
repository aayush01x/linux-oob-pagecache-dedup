#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "common.h"

/*
 * TEST: Full-page overwrite after dedup.
 *
 * The previous test only wrote partial pages. This test writes a complete
 * 4K page of different data to a deduped file and verifies:
 * 1. The full overwrite succeeds (COW break + write).
 * 2. The written data is correctly read back.
 * 3. The other deduped file is completely untouched.
 * 4. Re-reading the written file after close+reopen also works.
 */

int main(void)
{
	long page_size = 4096;
	int pass = 1;

	char *blk_a = malloc(page_size);
	char *blk_z = malloc(page_size);
	memset(blk_a, 'A', page_size);
	memset(blk_z, 'Z', page_size);

	char *pages[] = { blk_a };

	printf("=== TEST: Full-Page Overwrite After Dedup ===\n\n");

	printf("[*] Creating 2 identical files...\n");
	create_and_queue("cow_full_1.txt", pages, 1, page_size);
	create_and_queue("cow_full_2.txt", pages, 1, page_size);

	printf("[*] Sleeping 5s for dedup...\n");
	sleep(5);

	printf("[*] Press Enter to overwrite file 1 with all 'Z'...\n");
	getchar();

	/* Full-page overwrite */
	int fd1 = open("cow_full_1.txt", O_RDWR);
	if (fd1 < 0) { perror("open"); return 1; }

	lseek(fd1, 0, SEEK_SET);
	ssize_t w = write(fd1, blk_z, page_size);
	if (w != page_size) {
		perror("    -> FAILED: full-page write");
		pass = 0;
	} else {
		printf("    -> OK: wrote %zd bytes\n", w);
	}

	/* Verify file 1 — should be all 'Z' */
	printf("\n[*] Verifying file 1 (should be all 'Z')...\n");
	char *verify = malloc(page_size);
	lseek(fd1, 0, SEEK_SET);
	read(fd1, verify, page_size);
	for (int i = 0; i < page_size; i++) {
		if (verify[i] != 'Z') {
			printf("    -> CORRUPTION at %d: '%c' not 'Z'\n", i, verify[i]);
			pass = 0;
			break;
		}
	}
	if (pass) printf("    -> file 1 = all 'Z' ✓\n");
	close(fd1);

	/* Verify file 2 — should still be all 'A' */
	printf("[*] Verifying file 2 (should be all 'A')...\n");
	int fd2 = open("cow_full_2.txt", O_RDONLY);
	read(fd2, verify, page_size);
	for (int i = 0; i < page_size; i++) {
		if (verify[i] != 'A') {
			printf("    -> CORRUPTION at %d: '%c' not 'A'\n", i, verify[i]);
			pass = 0;
			break;
		}
	}
	if (pass) printf("    -> file 2 = all 'A' ✓\n");
	close(fd2);

	/* Re-open file 1 and verify again (tests persistence) */
	printf("[*] Re-opening file 1 to verify persistence...\n");
	fd1 = open("cow_full_1.txt", O_RDONLY);
	memset(verify, 0, page_size);
	read(fd1, verify, page_size);
	for (int i = 0; i < page_size; i++) {
		if (verify[i] != 'Z') {
			printf("    -> PERSISTENCE FAIL at %d: '%c' not 'Z'\n",
			       i, verify[i]);
			pass = 0;
			break;
		}
	}
	if (pass) printf("    -> file 1 re-read = all 'Z' ✓\n");
	close(fd1);

	printf("\n========================================\n");
	if (pass)
		printf("RESULT: ALL CHECKS PASSED ✓\n");
	else
		printf("RESULT: SOME CHECKS FAILED ✗\n");
	printf("========================================\n");

	printf("\n[*] Press Enter to clean up...\n");
	getchar();

	remove("cow_full_1.txt");
	remove("cow_full_2.txt");
	free(blk_a);
	free(blk_z);
	free(verify);

	printf("Test finished.\n");
	return pass ? 0 : 1;
}
