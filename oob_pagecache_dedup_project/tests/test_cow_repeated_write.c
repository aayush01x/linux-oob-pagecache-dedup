#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "common.h"

/*
 * TEST: Repeated COW — write to the same deduped file multiple times.
 *
 * After the first write triggers COW, subsequent writes should go directly
 * to the now-private folio without triggering COW again. Verifies that:
 * 1. The first write triggers COW break (check dmesg).
 * 2. The second write does NOT trigger COW (folio is already private).
 * 3. All data is correct after multiple writes.
 */

int main(void)
{
	long page_size = 4096;
	int pass = 1;

	char *blk_a = malloc(page_size);
	memset(blk_a, 'A', page_size);

	char *pages[] = { blk_a };

	printf("=== TEST: Repeated Writes After COW Break ===\n\n");

	printf("[*] Creating 2 identical files...\n");
	create_and_queue("cow_repeat_1.txt", pages, 1, page_size);
	create_and_queue("cow_repeat_2.txt", pages, 1, page_size);

	printf("[*] Sleeping 5s for dedup...\n");
	sleep(5);

	printf("[*] Press Enter to start writes...\n");
	getchar();

	int fd1 = open("cow_repeat_1.txt", O_RDWR);
	if (fd1 < 0) { perror("open"); return 1; }

	/* Write 1: triggers COW */
	printf("[*] Write 1: 128 bytes of 'B' at offset 0...\n");
	char buf_b[128];
	memset(buf_b, 'B', 128);
	lseek(fd1, 0, SEEK_SET);
	ssize_t w = write(fd1, buf_b, 128);
	if (w < 0) { perror("write 1 failed"); pass = 0; }
	else printf("    -> wrote %zd bytes (COW should trigger — check dmesg)\n", w);

	/* Write 2: should NOT trigger COW (folio is now private) */
	printf("[*] Write 2: 128 bytes of 'C' at offset 256...\n");
	char buf_c[128];
	memset(buf_c, 'C', 128);
	lseek(fd1, 256, SEEK_SET);
	w = write(fd1, buf_c, 128);
	if (w < 0) { perror("write 2 failed"); pass = 0; }
	else printf("    -> wrote %zd bytes (should NOT trigger COW)\n", w);

	/* Write 3: another non-COW write */
	printf("[*] Write 3: 64 bytes of 'D' at offset 3000...\n");
	char buf_d[64];
	memset(buf_d, 'D', 64);
	lseek(fd1, 3000, SEEK_SET);
	w = write(fd1, buf_d, 64);
	if (w < 0) { perror("write 3 failed"); pass = 0; }
	else printf("    -> wrote %zd bytes\n", w);

	/* Verify file 1 */
	printf("\n[*] Verifying file 1 data...\n");
	char *verify = malloc(page_size);
	lseek(fd1, 0, SEEK_SET);
	read(fd1, verify, page_size);

	/* Expected layout:
	 * [0:128]     = 'B'
	 * [128:256]   = 'A'
	 * [256:384]   = 'C'
	 * [384:3000]  = 'A'
	 * [3000:3064] = 'D'
	 * [3064:4096] = 'A'
	 */
	struct {
		int off; int len; char exp; const char *label;
	} checks[] = {
		{ 0,    128, 'B', "[0:128]=B" },
		{ 128,  128, 'A', "[128:256]=A" },
		{ 256,  128, 'C', "[256:384]=C" },
		{ 384,  100, 'A', "[384:484]=A" },
		{ 3000,  64, 'D', "[3000:3064]=D" },
		{ 3064,  32, 'A', "[3064:3096]=A" },
	};

	for (int i = 0; i < 6; i++) {
		int ok = 1;
		for (int j = 0; j < checks[i].len; j++) {
			if (verify[checks[i].off + j] != checks[i].exp) {
				printf("    -> FAIL: %s — byte %d is '%c' not '%c'\n",
				       checks[i].label, checks[i].off + j,
				       verify[checks[i].off + j], checks[i].exp);
				ok = 0; pass = 0;
				break;
			}
		}
		if (ok)
			printf("    -> %s ✓\n", checks[i].label);
	}
	close(fd1);

	/* Verify file 2 is still all A's */
	printf("\n[*] Verifying file 2 is untouched...\n");
	int fd2 = open("cow_repeat_2.txt", O_RDONLY);
	read(fd2, verify, page_size);
	int ok2 = 1;
	for (int i = 0; i < page_size; i++) {
		if (verify[i] != 'A') {
			printf("    -> CORRUPTION at offset %d: '%c' should be 'A'\n",
			       i, verify[i]);
			ok2 = 0; pass = 0;
			break;
		}
	}
	if (ok2) printf("    -> file 2 = all 'A' ✓\n");
	close(fd2);

	printf("\n========================================\n");
	if (pass)
		printf("RESULT: ALL CHECKS PASSED ✓\n");
	else
		printf("RESULT: SOME CHECKS FAILED ✗\n");
	printf("========================================\n");

	printf("\n[*] Press Enter to clean up...\n");
	getchar();

	remove("cow_repeat_1.txt");
	remove("cow_repeat_2.txt");
	free(blk_a);
	free(verify);

	printf("Test finished. Check dmesg — expect exactly 1 COW break message.\n");
	return pass ? 0 : 1;
}
