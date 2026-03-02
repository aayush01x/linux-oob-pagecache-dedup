set -e

cleanup_files() {
    rm -f test0_internal.txt
    rm -f test1_file1.txt test1_file2.txt
    rm -f folder_alpha/test2_file1.txt
    rm -f folder_beta/test2_file2.txt
    rm -f folder_alpha/test3_file1.txt
    rm -f folder_beta/test3_file2.txt
    rm -f folder_gamma/test3_file3.txt

    rm -rf folder_alpha folder_beta folder_gamma

}

compile_tests() {
    echo "Compiling tests..."
    gcc test0_internal.c common.c -o test0
    gcc test1_same_folder.c common.c -o test1
    gcc test2_diff_folders.c common.c -o test2
    gcc test3_multi_files.c common.c -o test3
}

run_test() {
    TEST_NAME=$1
    EXEC=$2

    echo "========================================"
    echo "Running $TEST_NAME"
    echo "========================================"

    cleanup_files

    echo "[*] Flushing filesystem..."
    sync

    echo "[*] Dropping page/inode/dentry caches..."
    echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null

    sleep 1

    sudo dmesg -C
    sleep 1

    sudo ./$EXEC

    sleep 1
    echo "---- DMESG OUTPUT ----"
    sudo dmesg
    echo ""

    cleanup_files

    echo "[*] Final cache drop..."
    sync
    echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
    sleep 1
}

cleanup_files

compile_tests

run_test "TEST 0 - Internal" test0
run_test "TEST 1 - Same Folder" test1
run_test "TEST 2 - Different Folders" test2
run_test "TEST 3 - Multi File" test3

rm -f test0 test1 test2 test3

echo "All tests completed."