#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "common.h"

/*
 * TEST: COW with multi-page files.
 *
 * Creates 2 identical files with 4 pages each (16K).
 * Writes to page 2 of file 1 only.
 * Verifies:
 * 1. File 1 pages 0,1,3 are still original 'A','B','D'.
 * 2. File 1 page 2 has the new data 'X'.
 * 3. File 2 is completely untouched (all original data).
 */

int main(void)
{
	long page_size = 4096;
	int pass = 1;

	/* 4 distinct pages to avoid accidental self-dedup */
	char *blk_a = malloc(page_size); memset(blk_a, 'A', page_size);
	char *blk_b = malloc(page_size); memset(blk_b, 'B', page_size);
	char *blk_c = malloc(page_size); memset(blk_c, 'C', page_size);
	char *blk_d = malloc(page_size); memset(blk_d, 'D', page_size);

	char *pages[] = { blk_a, blk_b, blk_c, blk_d };

	printf("=== TEST: COW on Multi-Page File (4 pages) ===\n\n");

	printf("[*] Creating 2 identical 16K files...\n");
	create_and_queue("cow_multipage_1.txt", pages, 4, page_size);
	create_and_queue("cow_multipage_2.txt", pages, 4, page_size);

	printf("[*] Sleeping 8s for dedup (4 pages to scan)...\n");
	sleep(8);

	printf("[*] Press Enter to write to page 2 of file 1...\n");
	getchar();

	/* Write to page index 2 (offset 8192) */
	int fd1 = open("cow_multipage_1.txt", O_RDWR);
	if (fd1 < 0) { perror("open"); return 1; }

	char *blk_x = malloc(page_size);
	memset(blk_x, 'X', page_size);
	lseek(fd1, 2 * page_size, SEEK_SET);
	ssize_t w = write(fd1, blk_x, page_size);
	if (w != page_size) {
		perror("    -> FAILED: write to page 2");
		pass = 0;
	} else {
		printf("    -> OK: wrote %zd bytes to page 2 of file 1\n", w);
	}

	/* Verify file 1 */
	printf("\n[*] Verifying file 1...\n");
	char *verify = malloc(page_size);
	char expected_f1[] = { 'A', 'B', 'X', 'D' };

	for (int p = 0; p < 4; p++) {
		lseek(fd1, p * page_size, SEEK_SET);
		read(fd1, verify, page_size);
		int ok = 1;
		for (int i = 0; i < page_size; i++) {
			if (verify[i] != expected_f1[p]) {
				printf("    -> FAIL: page %d byte %d = '%c' expected '%c'\n",
				       p, i, verify[i], expected_f1[p]);
				ok = 0; pass = 0;
				break;
			}
		}
		if (ok) printf("    -> page %d = '%c' ✓\n", p, expected_f1[p]);
	}
	close(fd1);

	/* Verify file 2 — all original */
	printf("[*] Verifying file 2 (all original)...\n");
	int fd2 = open("cow_multipage_2.txt", O_RDONLY);
	char expected_f2[] = { 'A', 'B', 'C', 'D' };

	for (int p = 0; p < 4; p++) {
		lseek(fd2, p * page_size, SEEK_SET);
		read(fd2, verify, page_size);
		int ok = 1;
		for (int i = 0; i < page_size; i++) {
			if (verify[i] != expected_f2[p]) {
				printf("    -> FAIL: page %d byte %d = '%c' expected '%c'\n",
				       p, i, verify[i], expected_f2[p]);
				ok = 0; pass = 0;
				break;
			}
		}
		if (ok) printf("    -> page %d = '%c' ✓\n", p, expected_f2[p]);
	}
	close(fd2);

	printf("\n========================================\n");
	if (pass)
		printf("RESULT: ALL CHECKS PASSED ✓\n");
	else
		printf("RESULT: SOME CHECKS FAILED ✗\n");
	printf("========================================\n");

	printf("\n[*] Press Enter to clean up...\n");
	getchar();

	remove("cow_multipage_1.txt");
	remove("cow_multipage_2.txt");
	free(blk_a); free(blk_b); free(blk_c); free(blk_d);
	free(blk_x); free(verify);

	printf("Test finished. Check dmesg — expect exactly 1 COW break (page 2 only).\n");
	return pass ? 0 : 1;
}
