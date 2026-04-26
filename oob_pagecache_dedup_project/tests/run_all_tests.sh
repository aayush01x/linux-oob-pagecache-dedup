#!/bin/bash
#
# run_all_tests.sh — Central test runner for OOB Page Cache Deduplication
#
# Compiles and runs ALL tests (C and shell) organized by category.
# Generates a test_report.md with PASS/FAIL summary.
#
# Usage:  sudo bash run_all_tests.sh [--category <name>] [--report]
#
#   --category <name>   Run only tests in the named category:
#                        basic, stress, regression, anchor, benchmark
#   --report            Generate test_report.md (default: on)
#
# Must be run as root from any directory. Requires gcc, sudo.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_SRC="$SCRIPT_DIR/clean_tests"
REPORT_FILE="$SCRIPT_DIR/test_report.md"

# ── Auto-detect XFS working directory ─────────────────────
if [ -z "$TEST_WORKDIR" ]; then
    XFS_MOUNT=$(findmnt -t xfs -n -o TARGET 2>/dev/null | head -1)
    TEST_WORKDIR="${XFS_MOUNT:-$TEST_SRC}"
fi
if [ ! -d "$TEST_WORKDIR" ]; then
    echo "[!] $TEST_WORKDIR does not exist. Falling back to $TEST_SRC."
    TEST_WORKDIR="$TEST_SRC"
fi

# ── Parse arguments ──────────────────────────────────────
FILTER_CATEGORY=""
GENERATE_REPORT=true
while [ $# -gt 0 ]; do
    case "$1" in
        --category) FILTER_CATEGORY="$2"; shift 2;;
        --report)   GENERATE_REPORT=true; shift;;
        *)          echo "Unknown arg: $1"; exit 1;;
    esac
done

# ── Counters ─────────────────────────────────────────────
PASS=0
FAIL=0
SKIP=0
TOTAL=0
declare -a RESULTS=()

# ── Helpers ──────────────────────────────────────────────
cleanup_workdir() {
    cd "$TEST_WORKDIR" 2>/dev/null || return
    rm -f cow_iso_file*.dat trunc_dedup_*.dat del_read_*.dat \
          sysfs_stat_*.dat fanout_*.dat large_folio_*.dat \
          intra_dedup_stress.dat cascade_*.dat \
          conc_tc_*.dat rededup_*.dat torture_*.dat \
          parttrunc_*.dat nfp_*.dat rapid_*.dat cowtrunc_*.dat \
          anchor_partial_*.dat stress_*.dat \
          dedup_test_*.dat large_dedup_*.dat
    cd "$SCRIPT_DIR"
}

compile_c() {
    local src="$1"
    local bin="${src%.c}"
    local extra="$2"
    gcc -Wall -Wextra -O2 -o "$TEST_WORKDIR/$bin" "$TEST_SRC/$src" $extra 2>&1 || {
        echo "  [COMPILE ERROR] $src"
        return 1
    }
}

run_c_test() {
    local category="$1"
    local num="$2"
    local name="$3"
    local src="$4"
    local extra="$5"
    local bin="${src%.c}"

    if [ -n "$FILTER_CATEGORY" ] && [ "$FILTER_CATEGORY" != "$category" ]; then
        return
    fi

    TOTAL=$((TOTAL + 1))
    echo ""
    echo "╔══════════════════════════════════════════════════════╗"
    printf "║  [%s] #%02d: %-40s ║\n" "$category" "$num" "$name"
    echo "╚══════════════════════════════════════════════════════╝"

    if ! compile_c "$src" "$extra"; then
        FAIL=$((FAIL + 1))
        RESULTS+=("FAIL|$category|$num|$name|$src|Compilation failed")
        return
    fi

    sync; sleep 1

    local T0=$(date +%s)
    cd "$TEST_WORKDIR"
    local STATUS=0
    sudo "./$bin" || STATUS=$?
    cd "$SCRIPT_DIR"
    local T1=$(date +%s)
    local ELAPSED=$((T1 - T0))

    # Cleanup binary
    rm -f "$TEST_WORKDIR/$bin"

    if [ "$STATUS" -eq 0 ]; then
        echo "  ✓ PASSED (${ELAPSED}s)"
        PASS=$((PASS + 1))
        RESULTS+=("PASS|$category|$num|$name|$src|${ELAPSED}s")
    else
        echo "  ✗ FAILED (exit=$STATUS, ${ELAPSED}s)"
        FAIL=$((FAIL + 1))
        RESULTS+=("FAIL|$category|$num|$name|$src|exit=$STATUS, ${ELAPSED}s")
    fi

    sleep 1
}

run_sh_test() {
    local category="$1"
    local num="$2"
    local name="$3"
    local src="$4"

    if [ -n "$FILTER_CATEGORY" ] && [ "$FILTER_CATEGORY" != "$category" ]; then
        return
    fi

    TOTAL=$((TOTAL + 1))
    echo ""
    echo "╔══════════════════════════════════════════════════════╗"
    printf "║  [%s] #%02d: %-40s ║\n" "$category" "$num" "$name"
    echo "╚══════════════════════════════════════════════════════╝"

    local T0=$(date +%s)
    local STATUS=0
    bash "$TEST_SRC/$src" || STATUS=$?
    local T1=$(date +%s)
    local ELAPSED=$((T1 - T0))

    if [ "$STATUS" -eq 0 ]; then
        echo "  ✓ PASSED (${ELAPSED}s)"
        PASS=$((PASS + 1))
        RESULTS+=("PASS|$category|$num|$name|$src|${ELAPSED}s")
    else
        echo "  ✗ FAILED (exit=$STATUS, ${ELAPSED}s)"
        FAIL=$((FAIL + 1))
        RESULTS+=("FAIL|$category|$num|$name|$src|exit=$STATUS, ${ELAPSED}s")
    fi
}

# ── Header ───────────────────────────────────────────────
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     OOB Page Cache Deduplication — Full Test Suite        ║"
echo "╠═══════════════════════════════════════════════════════════╣"
echo "║  Source:  $TEST_SRC"
echo "║  WorkDir: $TEST_WORKDIR"
echo "║  Filter:  ${FILTER_CATEGORY:-all}"
echo "╚═══════════════════════════════════════════════════════════╝"

COMMON="$TEST_SRC/common.c"

# ── Cleanup before run ───────────────────────────────────
cleanup_workdir

# ═══════════════════════════════════════════════════════════
#   CATEGORY: basic — Core functionality tests
# ═══════════════════════════════════════════════════════════

run_c_test "basic" 1  "COW Isolation"          test_01_cow_isolation.c       "$COMMON"
run_c_test "basic" 2  "Truncate Deduped File"  test_02_truncate_deduped.c    "$COMMON"
run_c_test "basic" 3  "Delete Then Read"       test_03_delete_then_read.c    "$COMMON"
run_c_test "basic" 4  "Sysfs Stats"            test_04_sysfs_stats.c         "$COMMON"
run_c_test "basic" 5  "Fanout COW (3-way)"     test_05_fanout_cow.c          "$COMMON"
run_c_test "basic" 6  "Large Folio Dedup+COW"  test_06_large_folio.c         ""

# ═══════════════════════════════════════════════════════════
#   CATEGORY: stress — Concurrency and edge-case tests
# ═══════════════════════════════════════════════════════════

run_c_test "stress" 7  "Intra-File Dedup"            test_07_intra_file_dedup.c      "$COMMON"
run_c_test "stress" 8  "Cascade Unlink (5-way)"      test_08_cascade_unlink.c        "$COMMON"
run_c_test "stress" 9  "Concurrent Trunc+COW"        test_09_concurrent_trunc_cow.c  "$COMMON"
run_c_test "stress" 10 "Re-Dedup After COW"          test_10_rededup_after_cow.c     "$COMMON"
run_c_test "stress" 11 "Combined Operations"         test_11_mixed_operations.c      "$COMMON"
run_c_test "stress" 12 "Partial Truncate"            test_12_partial_truncate.c      "$COMMON"

# ═══════════════════════════════════════════════════════════
#   CATEGORY: regression — Bug-triggering regression tests
# ═══════════════════════════════════════════════════════════

run_c_test "regression" 13 "Page Accounting"         test_13_page_accounting.c      "$COMMON"
run_c_test "regression" 14 "Rapid Lifecycle"          test_14_rapid_lifecycle.c       "$COMMON"
run_c_test "regression" 15 "COW During Truncate"      test_15_cow_during_truncate.c  "$COMMON"

# ═══════════════════════════════════════════════════════════
#   CATEGORY: anchor — Anchor hashing tests
# ═══════════════════════════════════════════════════════════

run_c_test "anchor" 16 "Anchor Partial Match"     test_16_anchor_partial_match.c "$COMMON"
run_c_test "anchor" 22 "Anchor Stress (COW+Trunc+Re-dedup)" test_22_anchor_stress.c "$COMMON"

# ═══════════════════════════════════════════════════════════
#   CATEGORY: benchmark — Memory savings and large file tests
# ═══════════════════════════════════════════════════════════

run_sh_test "benchmark" 18 "Memory Savings"            test_18_memory_savings.sh
run_sh_test "benchmark" 19 "Large File Dedup"           test_19_large_file_dedup.sh
run_sh_test "benchmark" 20 "Anchor Trace"               test_20_anchor_trace.sh
run_sh_test "benchmark" 21 "Intra-File Large Dedup"     test_21_intra_file_large_dedup.sh

# ── Cleanup after run ────────────────────────────────────
cleanup_workdir

# ═══════════════════════════════════════════════════════════
#   SUMMARY
# ═══════════════════════════════════════════════════════════

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                    TEST RESULTS                          ║"
echo "╠═══════════════════════════════════════════════════════════╣"
printf "║   TOTAL:   %-4d                                         ║\n" "$TOTAL"
printf "║   PASSED:  %-4d  ✓                                     ║\n" "$PASS"
printf "║   FAILED:  %-4d  ✗                                     ║\n" "$FAIL"
echo "╚═══════════════════════════════════════════════════════════╝"

# ── Generate Report ──────────────────────────────────────
if $GENERATE_REPORT; then
    {
        echo "# OOB Page Cache Deduplication — Test Report"
        echo ""
        echo "**Date**: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "**Kernel**: $(uname -r 2>/dev/null || echo 'N/A')"
        echo "**Hostname**: $(hostname 2>/dev/null || echo 'N/A')"
        echo "**Work Directory**: $TEST_WORKDIR"
        echo ""
        echo "## Summary"
        echo ""
        echo "| Metric | Count |"
        echo "|--------|-------|"
        echo "| Total  | $TOTAL |"
        echo "| Passed | $PASS |"
        echo "| Failed | $FAIL |"
        echo ""
        echo "## Detailed Results"
        echo ""
        echo "| # | Category | Test Name | Source | Result | Time/Notes |"
        echo "|---|----------|-----------|--------|--------|------------|"
        for r in "${RESULTS[@]}"; do
            IFS='|' read -r status cat num name src notes <<< "$r"
            if [ "$status" = "PASS" ]; then
                printf "| %s | %s | %s | \`%s\` | ✅ PASS | %s |\n" "$num" "$cat" "$name" "$src" "$notes"
            else
                printf "| %s | %s | %s | \`%s\` | ❌ FAIL | %s |\n" "$num" "$cat" "$name" "$src" "$notes"
            fi
        done
        echo ""
        echo "## Test Categories"
        echo ""
        echo "- **basic**: Core functionality — COW, truncation, deletion, sysfs, fanout, large folios"
        echo "- **stress**: Concurrency and edge-case stress — intra-file, cascade, concurrent ops, torture"
        echo "- **regression**: Bug-triggering tests — NR_FILE_PAGES leak, rapid cycles, COW during truncate"
        echo "- **anchor**: Anchor-based hashing — partial match detection, multi-similarity stress"
        echo "- **benchmark**: Memory savings and large file — real-world workload demonstrations"
    } > "$REPORT_FILE"
    echo ""
    echo "Report written to: $REPORT_FILE"
fi

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "⚠  SOME TESTS FAILED"
    exit 1
fi

echo ""
echo "✓ ALL TESTS PASSED"
exit 0
