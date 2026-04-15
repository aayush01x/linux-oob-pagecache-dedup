#!/bin/bash
set -e

# --- Config ---
EXEC="test_delete_exec"

cleanup_data() {
    echo "[*] Cleaning up data files..."
    rm -f file_to_del_1.txt file_to_del_2.txt
}

deep_clean() {
    cleanup_data
    rm -f $EXEC
}

compile_tests() {
    echo "[*] Compiling deletion test..."
    gcc test_delete.c common.c -o $EXEC
}

run_test() {
    echo "========================================"
    echo "Running Deletion Stress Test"
    echo "========================================"

    # Ensure no stale data exists
    cleanup_data
    sync

    # Clear logs
    sudo dmesg -C
    echo "[*] dmesg cleared."

    # Execute
    sudo ./$EXEC

    echo ""
    echo "---- KERNEL LOGS ----"
    sudo dmesg | tail -n 20
    echo "---------------------"

    cleanup_data
}

# --- Main ---
# Remove binary on exit
trap deep_clean EXIT

compile_tests
run_test

echo "Test sequence finished successfully."
