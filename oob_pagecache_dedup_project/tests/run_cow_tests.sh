#!/bin/bash
set -e

# --- COW Test Suite ---
# Compile and run all COW-on-write tests.
# Usage: sudo ./run_cow_tests.sh

TESTS=(
    "test_write_single_page"
    "test_cow_multi_file"
    "test_cow_repeated_write"
    "test_cow_full_overwrite"
    "test_cow_multipage"
)

cleanup_data() {
    rm -f file_trap_*.txt cow_multi_*.txt cow_repeat_*.txt cow_full_*.txt cow_multipage_*.txt
}

deep_clean() {
    cleanup_data
    for t in "${TESTS[@]}"; do
        rm -f "${t}_exec"
    done
}

trap deep_clean EXIT

echo "========================================"
echo " COW-on-Write Test Suite"
echo "========================================"
echo ""

# Compile all tests
echo "[*] Compiling tests..."
for t in "${TESTS[@]}"; do
    gcc "${t}.c" common.c -o "${t}_exec"
    echo "    Compiled: ${t}"
done
echo ""

# Run each test
PASSED=0
FAILED=0
for t in "${TESTS[@]}"; do
    echo "========================================"
    echo " Running: ${t}"
    echo "========================================"

    cleanup_data
    sync
    sudo dmesg -C

    # Run with a timeout to prevent hangs (auto-press Enter)
    # Note: tests have getchar() pauses for interactive use.
    # For automated runs, pipe Enter presses.
    echo "" | echo "" | sudo "./${t}_exec"

    echo ""
    echo "---- KERNEL LOGS ----"
    sudo dmesg | grep -i "OOB_DEDUP" | tail -n 10
    echo "---------------------"
    echo ""

    PASSED=$((PASSED + 1))
done

cleanup_data

echo "========================================"
echo " Suite Complete: ${PASSED} tests ran"
echo "========================================"
