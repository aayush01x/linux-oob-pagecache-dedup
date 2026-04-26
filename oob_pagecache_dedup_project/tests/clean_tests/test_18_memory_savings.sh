#!/bin/bash
# test_memory_savings.sh — Visually verify dedup frees memory
# Run this on the VM while watching /proc/meminfo in another terminal

set -e
# Prefer XFS for large folio support (faster truncation of deduped files).
# Override: TEST_DIR=/your/path sudo bash test_memory_savings.sh
if [ -z "$TEST_DIR" ]; then
    XFS_MOUNT=$(findmnt -t xfs -n -o TARGET | head -1)
    TEST_DIR="${XFS_MOUNT:-/tmp}/dedup_test"
fi
NUM_FILES=10
FILE_SIZE_MB=20  # Each file = 20 MB, total = 200 MB of identical data
FILL_CHAR="A"

mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

echo "============================================"
echo "  Memory Savings Verification Test"
echo "============================================"

# Step 0: Drop caches to get a clean baseline
echo "[0] Dropping caches for clean baseline..."
sync
echo 3 > /proc/sys/vm/drop_caches
sleep 2

echo ""
echo "--- BASELINE (no test files) ---"
grep -E "MemFree|MemAvailable|Cached" /proc/meminfo
CACHED_BEFORE=$(awk '/^Cached:/ {print $2}' /proc/meminfo)
echo ""

# Step 1: Create N identical large files
echo "[1] Creating $NUM_FILES identical ${FILE_SIZE_MB}MB files..."
for i in $(seq 1 $NUM_FILES); do
    dd if=/dev/zero bs=1M count=$FILE_SIZE_MB 2>/dev/null | tr '\0' "$FILL_CHAR" > "dedup_test_$i.dat"
    echo "  Created dedup_test_$i.dat"
done

# Flush dirty pages AND release buffer_heads:
# sync writes data to disk, drop_caches releases buffer_heads & page cache
echo "[*] Syncing + dropping caches to release buffer_heads..."
sync
echo 3 > /proc/sys/vm/drop_caches
sleep 2

# Re-read files into page cache (now clean, no buffer_heads)
echo "[2] Reading all files into clean page cache..."
for i in $(seq 1 $NUM_FILES); do
    cat "dedup_test_$i.dat" > /dev/null
done

# Measure BEFORE queuing for dedup — the scanner starts immediately
# on fadvise, so we must capture the full cache footprint first.
echo ""
echo "--- AFTER LOADING (before dedup) ---"
grep -E "MemFree|MemAvailable|Cached" /proc/meminfo
CACHED_AFTER_LOAD=$(awk '/^Cached:/ {print $2}' /proc/meminfo)
CONSUMED=$(( (CACHED_AFTER_LOAD - CACHED_BEFORE) / 1024 ))
echo "  -> ~${CONSUMED} MB consumed by page cache"
echo ""

# Queue for dedup AFTER measuring the pre-dedup baseline
echo "[*] Queueing files for dedup..."
for i in $(seq 1 $NUM_FILES); do
    python3 -c "
import os, ctypes
POSIX_FADV_DEDUP = 8
fd = os.open('dedup_test_$i.dat', os.O_RDONLY)
libc = ctypes.CDLL('libc.so.6')
libc.posix_fadvise(fd, 0, 0, POSIX_FADV_DEDUP)
os.close(fd)
" 2>/dev/null || true
    echo "  [+] Queued dedup_test_$i.dat"
done

# Step 3: Wait for scanner
WAIT=30
echo "[3] Waiting ${WAIT}s for dedup scanner..."
for i in $(seq 1 $WAIT); do
    printf "\r    %d/%d seconds..." "$i" "$WAIT"
    sleep 1
done
echo ""

echo ""
echo "--- AFTER DEDUP ---"
grep -E "MemFree|MemAvailable|Cached" /proc/meminfo
CACHED_AFTER_DEDUP=$(awk '/^Cached:/ {print $2}' /proc/meminfo)
SAVED=$(( (CACHED_AFTER_LOAD - CACHED_AFTER_DEDUP) / 1024 ))
echo "  -> ~${SAVED} MB freed by dedup"
echo ""

# Step 4: Show dedup stats
echo "--- DEDUP STATS ---"
if [ -d /sys/kernel/oob_dedup ]; then
    for f in /sys/kernel/oob_dedup/*; do
        echo "  $(basename $f) = $(cat $f)"
    done
else
    echo "  (sysfs stats not available)"
fi

# Step 5: Verify data integrity
echo ""
echo "[4] Verifying all files still readable and correct..."
PASS=true
for i in $(seq 1 $NUM_FILES); do
    EXPECTED=$(( FILE_SIZE_MB * 1024 * 1024 ))
    ACTUAL=$(wc -c < "dedup_test_$i.dat")
    SAMPLE=$(head -c 1 "dedup_test_$i.dat")
    if [ "$ACTUAL" -eq "$EXPECTED" ] && [ "$SAMPLE" = "$FILL_CHAR" ]; then
        echo "  dedup_test_$i.dat: OK (${FILE_SIZE_MB}MB, fill='$FILL_CHAR')"
    else
        echo "  dedup_test_$i.dat: FAIL (size=$ACTUAL, sample=$SAMPLE)"
        PASS=false
    fi
done

# Cleanup
echo ""
echo "[5] Cleaning up..."
rm -f "$TEST_DIR"/dedup_test_*.dat

echo ""
if $PASS; then
    echo "============================================"
    echo "  RESULT: ${CONSUMED}MB loaded -> ${SAVED}MB freed by dedup"
    echo "============================================"
else
    echo "[FAIL] Data integrity check failed!"
fi
