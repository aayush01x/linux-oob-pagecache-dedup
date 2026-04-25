#!/bin/bash
#
# run_clean_tests.sh
#
# Compiles and runs all clean_tests for OOB page-cache dedup.
# Must be executed from the clean_tests/ directory.
# Requires: gcc, sudo (tests need fadvise to reach the kernel).
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Run tests on XFS for large folio support (faster truncation of deduped files).
# XFS creates order-4 folios (64KB) which dramatically reduces rmap list sizes.
# Override: TEST_WORKDIR=/your/path bash run_clean_tests.sh
if [ -z "$TEST_WORKDIR" ]; then
    XFS_MOUNT=$(findmnt -t xfs -n -o TARGET | head -1)
    TEST_WORKDIR="${XFS_MOUNT:-$SCRIPT_DIR}"
fi
if [ ! -d "$TEST_WORKDIR" ]; then
    echo "[!] $TEST_WORKDIR does not exist. Falling back to script directory."
    TEST_WORKDIR="$SCRIPT_DIR"
fi

# Compile in source dir, run tests in XFS workdir
cd "$SCRIPT_DIR"

PASS=0
FAIL=0
SKIP=0

# ---------- helpers ----------
cleanup_all() {
    cd "$TEST_WORKDIR"
    rm -f cow_iso_file*.dat trunc_dedup_*.dat del_read_*.dat \
          sysfs_stat_*.dat fanout_*.dat large_folio_*.dat \
          intra_dedup_stress.dat cascade_*.dat \
          conc_tc_*.dat rededup_*.dat torture_*.dat \
          parttrunc_*.dat nfp_*.dat rapid_*.dat cowtrunc_*.dat \
          interfile_shuf_*.dat
    cd "$SCRIPT_DIR"
}

compile() {
    local src="$1"
    local bin="${src%.c}"
    local extra="$2"
    echo "  Compiling $src ..."
    gcc -Wall -Wextra -O2 -o "$TEST_WORKDIR/$bin" "$src" $extra
}

run_one() {
    local name="$1"
    local bin="$2"

    echo ""
    echo "========================================"
    echo "  $name"
    echo "========================================"

    sync
    sleep 1

    cd "$TEST_WORKDIR"
    if sudo "./$bin"; then
        PASS=$((PASS + 1))
    else
        echo "  *** FAILED ***"
        FAIL=$((FAIL + 1))
    fi
    cd "$SCRIPT_DIR"

    sleep 1
}

# ---------- compile ----------
echo "[*] Compiling all clean tests..."

# Tests that use common.c
for src in test_cow_isolation_auto.c \
           test_truncate_deduped.c \
           test_delete_then_read.c \
           test_sysfs_stats_auto.c \
           test_fanout_cow.c \
           test_intra_file_dedup.c \
           test_cascade_unlink.c \
           test_concurrent_trunc_cow.c \
           test_rededup_after_cow.c \
           test_mixed_ops_torture.c \
           test_partial_truncate_dedup.c \
           test_nr_file_pages_leak.c \
           test_rapid_dedup_delete.c \
           test_cow_during_truncate.c \
           test_interfile_shuffled.c; do
    compile "$src" "common.c"
done

# Standalone test (no common.c)
compile test_large_folio.c ""

echo "[*] Compilation done."
echo ""

# ---------- run ----------
cleanup_all

run_one "COW Isolation (Auto)"      test_cow_isolation_auto
run_one "Truncate Deduped"          test_truncate_deduped
run_one "Delete Then Read"          test_delete_then_read
run_one "Sysfs Stats (Auto)"        test_sysfs_stats_auto
run_one "Fanout COW (3-way)"        test_fanout_cow
run_one "Large Folio Dedup+COW"     test_large_folio

# ---------- stress tests ----------
run_one "Intra-File Dedup Stress"   test_intra_file_dedup
run_one "Cascade Unlink (5-way)"    test_cascade_unlink
run_one "Concurrent Trunc+COW"      test_concurrent_trunc_cow
run_one "Re-Dedup After COW"        test_rededup_after_cow
run_one "Mixed Ops Torture"         test_mixed_ops_torture
run_one "Partial Truncate Dedup"    test_partial_truncate_dedup

# ---------- bug-triggering tests ----------
run_one "NR_FILE_PAGES Leak"        test_nr_file_pages_leak
run_one "Rapid Dedup-Delete"        test_rapid_dedup_delete
run_one "COW During Truncate"       test_cow_during_truncate
run_one "Inter-File Shuffled"       test_interfile_shuffled

# ---------- summary ----------
cleanup_all

echo ""
echo "========================================"
echo "  RESULTS"
echo "========================================"
echo "  PASSED : $PASS"
echo "  FAILED : $FAIL"
echo "  SKIPPED: $SKIP"
echo "========================================"

# Clean up binaries
cd "$TEST_WORKDIR"
rm -f test_cow_isolation_auto test_truncate_deduped test_delete_then_read \
      test_sysfs_stats_auto test_fanout_cow test_large_folio \
      test_intra_file_dedup test_cascade_unlink test_concurrent_trunc_cow \
      test_rededup_after_cow test_mixed_ops_torture \
      test_partial_truncate_dedup \
      test_nr_file_pages_leak test_rapid_dedup_delete test_cow_during_truncate \
      test_interfile_shuffled
cd "$SCRIPT_DIR"

if [ "$FAIL" -gt 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
fi

echo "ALL TESTS PASSED"
exit 0
