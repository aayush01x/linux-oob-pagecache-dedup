#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "common.h"

/*
 * TEST: COW isolation across 3 identical files (N-way dedup).
 *
 * 1. Create 3 identical 4K files filled with 'A'.
 * 2. Wait for dedup to merge them.
 * 3. Write 'X' to file 1, 'Y' to file 2, leave file 3 untouched.
 * 4. Verify each file has the correct data — no cross-contamination.
 */

static int verify_byte_range(int fd, off_t offset, size_t len, char expected,
			     const char *file_label)
{
	char *buf = malloc(len);
	if (!buf) return -1;

	lseek(fd, offset, SEEK_SET);
	if (read(fd, buf, len) != (ssize_t)len) {
		perror("read");
		free(buf);
		return -1;
	}

	int ok = 1;
	for (size_t i = 0; i < len; i++) {
		if (buf[i] != expected) {
			printf("    -> %s: CORRUPTION at offset %lu: "
			       "expected '%c' (0x%02x), got '%c' (0x%02x)\n",
			       file_label, (unsigned long)(offset + i),
			       expected, (unsigned char)expected,
			       buf[i], (unsigned char)buf[i]);
			ok = 0;
			break;
		}
	}
	free(buf);
	return ok ? 0 : -1;
}

int main(void)
{
	long page_size = 4096;
	int pass = 1;

	char *blk_a = malloc(page_size);
	memset(blk_a, 'A', page_size);

	char *pages[] = { blk_a };

	printf("=== TEST: COW Isolation — 3-Way Dedup ===\n\n");

	/* Phase 1: Create 3 identical files */
	printf("[*] Creating 3 identical files...\n");
	create_and_queue("cow_multi_1.txt", pages, 1, page_size);
	create_and_queue("cow_multi_2.txt", pages, 1, page_size);
	create_and_queue("cow_multi_3.txt", pages, 1, page_size);

	printf("[*] Sleeping 6s for background dedup...\n");
	sleep(6);

	printf("[*] Press Enter to write to files 1 and 2...\n");
	getchar();

	/* Phase 2: Write 'X' to file 1 at offset 0 */
	printf("[*] Writing 512 bytes of 'X' to file 1 at offset 0...\n");
	int fd1 = open("cow_multi_1.txt", O_RDWR);
	if (fd1 < 0) { perror("open file 1"); return 1; }

	char *blk_x = malloc(512);
	memset(blk_x, 'X', 512);
	lseek(fd1, 0, SEEK_SET);
	ssize_t w1 = write(fd1, blk_x, 512);
	if (w1 < 0) {
		perror("    -> FAILED: write to file 1");
		pass = 0;
	} else {
		printf("    -> OK: wrote %zd bytes to file 1\n", w1);
	}

	/* Phase 3: Write 'Y' to file 2 at offset 2048 */
	printf("[*] Writing 256 bytes of 'Y' to file 2 at offset 2048...\n");
	int fd2 = open("cow_multi_2.txt", O_RDWR);
	if (fd2 < 0) { perror("open file 2"); return 1; }

	char *blk_y = malloc(256);
	memset(blk_y, 'Y', 256);
	lseek(fd2, 2048, SEEK_SET);
	ssize_t w2 = write(fd2, blk_y, 256);
	if (w2 < 0) {
		perror("    -> FAILED: write to file 2");
		pass = 0;
	} else {
		printf("    -> OK: wrote %zd bytes to file 2\n", w2);
	}

	/* Phase 4: Verify all 3 files */
	printf("\n[*] Verifying data integrity...\n");

	/* File 1: [XXXX...512][AAAA...3584] */
	printf("  File 1:\n");
	if (verify_byte_range(fd1, 0, 512, 'X', "file1[0:512]") == 0)
		printf("    -> file1[0:512] = 'X' ✓\n");
	else pass = 0;
	if (verify_byte_range(fd1, 512, page_size - 512, 'A', "file1[512:4096]") == 0)
		printf("    -> file1[512:4096] = 'A' ✓\n");
	else pass = 0;
	close(fd1);

	/* File 2: [AAAA...2048][YYYY...256][AAAA...1792] */
	printf("  File 2:\n");
	if (verify_byte_range(fd2, 0, 2048, 'A', "file2[0:2048]") == 0)
		printf("    -> file2[0:2048] = 'A' ✓\n");
	else pass = 0;
	if (verify_byte_range(fd2, 2048, 256, 'Y', "file2[2048:2304]") == 0)
		printf("    -> file2[2048:2304] = 'Y' ✓\n");
	else pass = 0;
	if (verify_byte_range(fd2, 2304, page_size - 2304, 'A', "file2[2304:4096]") == 0)
		printf("    -> file2[2304:4096] = 'A' ✓\n");
	else pass = 0;
	close(fd2);

	/* File 3: ALL 'A' — completely untouched */
	printf("  File 3:\n");
	int fd3 = open("cow_multi_3.txt", O_RDONLY);
	if (fd3 < 0) { perror("open file 3"); return 1; }
	if (verify_byte_range(fd3, 0, page_size, 'A', "file3[0:4096]") == 0)
		printf("    -> file3[0:4096] = 'A' ✓ (untouched)\n");
	else pass = 0;
	close(fd3);

	printf("\n========================================\n");
	if (pass)
		printf("RESULT: ALL CHECKS PASSED ✓\n");
	else
		printf("RESULT: SOME CHECKS FAILED ✗\n");
	printf("========================================\n");

	printf("\n[*] Press Enter to clean up...\n");
	getchar();

	remove("cow_multi_1.txt");
	remove("cow_multi_2.txt");
	remove("cow_multi_3.txt");

	free(blk_a);
	free(blk_x);
	free(blk_y);

	printf("Test finished. Check dmesg for COW break messages.\n");
	return pass ? 0 : 1;
}
