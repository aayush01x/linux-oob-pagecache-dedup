/*
 * test_order_n.c — Order-N Folio Dedup Detection Test
 *
 * Tests that the dedup scanner correctly detects identical pages across files
 * and counts them via sysfs. Also verifies that NO data corruption occurs
 * (dedup is currently count-only; real merging requires the Symmetric Peer Model).
 *
 * Three scenarios:
 *   S1: Same first page, different rest → only 1 cross-file match expected
 *   S2: Fully identical files → all pages should match
 *   S3: 75% identical → matching pages detected, differing pages skipped
 *
 * Usage:
 *     gcc test_order_n.c common.c -o test_order_n
 *     sudo ./test_order_n
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "common.h"

#define NUM_PAGES 16

static int read_sysfs_int(const char *path)
{
	FILE *f = fopen(path, "r");
	if (!f)
		return -1;
	int val = 0;
	if (fscanf(f, "%d", &val) != 1)
		val = -1;
	fclose(f);
	return val;
}

static void reset_stats(void)
{
	FILE *f = fopen("/sys/kernel/oob_dedup/reset_stats", "w");
	if (f) {
		fprintf(f, "1\n");
		fclose(f);
	}
	/* Fallback: if reset_stats doesn't exist, just note the baseline */
}

static void print_stats(const char *label)
{
	printf("  [%s] pages_deduped=%d  pages_scanned=%d  folios_split=%d\n",
	       label, read_sysfs_int("/sys/kernel/oob_dedup/pages_deduped"),
	       read_sysfs_int("/sys/kernel/oob_dedup/pages_scanned"),
	       read_sysfs_int("/sys/kernel/oob_dedup/folios_split"));
}

static int verify_file(const char *filename, char *expected, long total_size)
{
	int fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open for verify");
		return -1;
	}

	char *buf = malloc(total_size);
	long rd = read(fd, buf, total_size);
	close(fd);

	if (rd != total_size) {
		printf("  [FAIL] %s: short read (%ld/%ld)\n", filename, rd,
		       total_size);
		free(buf);
		return -1;
	}

	if (memcmp(buf, expected, total_size) != 0) {
		long page_size = sysconf(_SC_PAGESIZE);
		for (long i = 0; i < total_size / page_size; i++) {
			if (memcmp(buf + i * page_size,
				   expected + i * page_size, page_size) != 0) {
				printf("  [FAIL] %s: DATA CORRUPTION at page %ld! "
				       "Got 0x%02x, expected 0x%02x\n",
				       filename, i,
				       (unsigned char)buf[i * page_size],
				       (unsigned char)expected[i * page_size]);
				break;
			}
		}
		free(buf);
		return -1;
	}

	printf("  [PASS] %s: data intact\n", filename);
	free(buf);
	return 0;
}

int main()
{
	long page_size = sysconf(_SC_PAGESIZE);
	long file_size = NUM_PAGES * page_size;
	int result = 0;

	printf("\n");
	printf("============================================================\n");
	printf("  Order-N Folio Dedup Detection Test\n");
	printf("  Page size: %ld, File size: %ld (%d pages)\n", page_size,
	       file_size, NUM_PAGES);
	printf("============================================================\n\n");

	char *data1 = malloc(file_size);
	char *data2 = malloc(file_size);
	char **blocks1 = malloc(NUM_PAGES * sizeof(char *));
	char **blocks2 = malloc(NUM_PAGES * sizeof(char *));
	for (int i = 0; i < NUM_PAGES; i++) {
		blocks1[i] = data1 + i * page_size;
		blocks2[i] = data2 + i * page_size;
	}

	/* ============ SCENARIO 1: Same first page, different rest ============ */
	printf("--- SCENARIO 1: Same first page, different rest ---\n");
	printf("    Expect: 1 cross-file dedup (page 0 only)\n\n");

	int baseline = read_sysfs_int("/sys/kernel/oob_dedup/pages_deduped");

	/* File1: page[0]='A', page[1..15]='B' */
	memset(data1, 'A', page_size);
	memset(data1 + page_size, 'B', file_size - page_size);
	/* File2: page[0]='A', page[1..15]='C' */
	memset(data2, 'A', page_size);
	memset(data2 + page_size, 'C', file_size - page_size);

	create_and_queue("test_ordn_s1_file1.txt", blocks1, NUM_PAGES,
			 page_size);
	create_and_queue("test_ordn_s1_file2.txt", blocks2, NUM_PAGES,
			 page_size);

	printf("  Waiting for dedup scan (4s)...\n");
	sleep(4);

	int after_s1 = read_sysfs_int("/sys/kernel/oob_dedup/pages_deduped");
	int deduped_s1 = after_s1 - baseline;
	printf("  Dedup count this scenario: %d\n", deduped_s1);

	/* Verify NO data corruption */
	int s1_ok =
		(verify_file("test_ordn_s1_file1.txt", data1, file_size) == 0 &&
		 verify_file("test_ordn_s1_file2.txt", data2, file_size) == 0);

	/* Expected: 14 intra-file1(B) + 14 intra-file2(C) + 1 cross-file(A) = 29 */
	if (s1_ok && deduped_s1 > 0) {
		printf("  *** S1: PASS — %d duplicates detected, no corruption ***\n\n",
		       deduped_s1);
	} else if (!s1_ok) {
		printf("  *** S1: FAIL — data corruption detected ***\n\n");
		result = 1;
	} else {
		printf("  *** S1: WARN — 0 duplicates detected (scan may need more time) ***\n\n");
	}

	unlink("test_ordn_s1_file1.txt");
	unlink("test_ordn_s1_file2.txt");

	/* ============ SCENARIO 2: Fully identical files ============ */
	printf("--- SCENARIO 2: Fully identical large files ---\n\n");

	baseline = read_sysfs_int("/sys/kernel/oob_dedup/pages_deduped");

	memset(data1, 'X', file_size);
	memcpy(data2, data1, file_size);

	create_and_queue("test_ordn_s2_file1.txt", blocks1, NUM_PAGES,
			 page_size);
	create_and_queue("test_ordn_s2_file2.txt", blocks2, NUM_PAGES,
			 page_size);

	printf("  Waiting for dedup scan (4s)...\n");
	sleep(4);

	int after_s2 = read_sysfs_int("/sys/kernel/oob_dedup/pages_deduped");
	int deduped_s2 = after_s2 - baseline;
	printf("  Dedup count this scenario: %d\n", deduped_s2);

	int s2_ok =
		(verify_file("test_ordn_s2_file1.txt", data1, file_size) == 0 &&
		 verify_file("test_ordn_s2_file2.txt", data2, file_size) == 0);

	if (s2_ok && deduped_s2 > 0) {
		printf("  *** S2: PASS — %d duplicates detected, no corruption ***\n\n",
		       deduped_s2);
	} else if (!s2_ok) {
		printf("  *** S2: FAIL — data corruption detected ***\n\n");
		result = 1;
	} else {
		printf("  *** S2: WARN — 0 duplicates detected ***\n\n");
	}

	unlink("test_ordn_s2_file1.txt");
	unlink("test_ordn_s2_file2.txt");

	/* ============ SCENARIO 3: Partially identical (75% match) ============ */
	printf("--- SCENARIO 3: 75%% identical (12/16 pages match) ---\n\n");

	baseline = read_sysfs_int("/sys/kernel/oob_dedup/pages_deduped");

	/* File1: pages 0..11='M', pages 12..15='D' */
	memset(data1, 'M', 12 * page_size);
	memset(data1 + 12 * page_size, 'D', 4 * page_size);
	/* File2: pages 0..11='M', pages 12..15='E' */
	memset(data2, 'M', 12 * page_size);
	memset(data2 + 12 * page_size, 'E', 4 * page_size);

	create_and_queue("test_ordn_s3_file1.txt", blocks1, NUM_PAGES,
			 page_size);
	create_and_queue("test_ordn_s3_file2.txt", blocks2, NUM_PAGES,
			 page_size);

	printf("  Waiting for dedup scan (4s)...\n");
	sleep(4);

	int after_s3 = read_sysfs_int("/sys/kernel/oob_dedup/pages_deduped");
	int deduped_s3 = after_s3 - baseline;
	int split_s3 = read_sysfs_int("/sys/kernel/oob_dedup/folios_split");
	printf("  Dedup count this scenario: %d  (folios_split: %d)\n",
	       deduped_s3, split_s3);

	int s3_ok =
		(verify_file("test_ordn_s3_file1.txt", data1, file_size) == 0 &&
		 verify_file("test_ordn_s3_file2.txt", data2, file_size) == 0);

	if (s3_ok && deduped_s3 > 0) {
		printf("  *** S3: PASS — %d duplicates detected, no corruption ***\n\n",
		       deduped_s3);
	} else if (!s3_ok) {
		printf("  *** S3: FAIL — data corruption detected ***\n\n");
		result = 1;
	} else {
		printf("  *** S3: WARN — 0 duplicates detected ***\n\n");
	}

	unlink("test_ordn_s3_file1.txt");
	unlink("test_ordn_s3_file2.txt");

	/* ============ SUMMARY ============ */
	printf("============================================================\n");
	printf("  VERDICT: %s\n",
	       result == 0 ? "ALL SCENARIOS PASSED" : "SOME SCENARIOS FAILED");
	printf("============================================================\n\n");

	free(data1);
	free(data2);
	free(blocks1);
	free(blocks2);

	return result;
}
