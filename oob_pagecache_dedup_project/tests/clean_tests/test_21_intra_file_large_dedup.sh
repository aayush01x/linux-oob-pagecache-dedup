#!/bin/bash
# test_explicit_dedup_large_file.sh
# Tests explicit intra-file deduplication for a 512MB file using sar -r
# Checks deduplication speed, memory savings, and nr_file_pages consistency

set -e

# Prefer XFS but ensure we have write access
if [ -z "$TEST_DIR" ]; then
  XFS_MOUNT=$(findmnt -t xfs -n -o TARGET | head -1)
  if [ -n "$XFS_MOUNT" ] && [ -w "$XFS_MOUNT" ]; then
    TEST_DIR="$XFS_MOUNT/dedup_test"
  else
    TEST_DIR="/tmp/dedup_test"
  fi
fi

FILE_SIZE_MB=512
FILENAME="large_dedup_512.dat"

mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

echo "=========================================================="
echo "  Explicit Large File Deduplication Test ($FILE_SIZE_MB MB)"
echo "=========================================================="

echo "[1] Creating ${FILE_SIZE_MB}MB file with identical data..."
dd if=/dev/zero bs=1M count=$FILE_SIZE_MB 2>/dev/null | tr '\0' 'A' >"$FILENAME"

echo "[2] Fsyncing file and dropping caches..."
# explicitly fsync the file
python3 -c "import os; fd = os.open('$FILENAME', os.O_RDWR); os.fsync(fd); os.close(fd)"
sync
echo 3 >/proc/sys/vm/drop_caches
sleep 2

NR_FILE_BEFORE=$(awk '/nr_file_pages/ {print $2}' /proc/vmstat)
CACHED_BEFORE=$(awk '/^Cached:/ {print $2}' /proc/meminfo)

echo "[3] Reading file into memory..."
cat "$FILENAME" >/dev/null

NR_FILE_LOADED=$(awk '/nr_file_pages/ {print $2}' /proc/vmstat)
CACHED_LOADED=$(awk '/^Cached:/ {print $2}' /proc/meminfo)
LOADED_MB=$(((CACHED_LOADED - CACHED_BEFORE) / 1024))

echo "    -> Loaded ~${LOADED_MB}MB into page cache."

echo "[4] Waiting before starting deduplication..."
sleep 5

echo "[5] Starting sar -r 1 to monitor memory in background..."
sar -r 1 60 >sar_output.txt &
SAR_PID=$!

echo "[6] Queueing file for explicit deduplication..."
python3 -c "
import os, ctypes
fd = os.open('$FILENAME', os.O_RDONLY)
libc = ctypes.CDLL('libc.so.6')
libc.posix_fadvise(fd, 0, 0, 8) # POSIX_FADV_DEDUP = 8
os.close(fd)
" 2>/dev/null || echo "    [!] posix_fadvise failed or not supported"

echo "[7] Waiting right after fadvise..."
sleep 5

# Track stats live
echo "[8] Waiting for deduplication to finish..."
echo "    Time | Files Queued | Pages Deduped | Cached MB | nr_file_pages"
START_TIME=$(date +%s)
while true; do
  QUEUED=$(cat /sys/kernel/oob_dedup/files_queued 2>/dev/null || echo "0")
  DEDUPED=$(cat /sys/kernel/oob_dedup/pages_deduped 2>/dev/null || echo "0")
  CUR_CACHED=$(($(awk '/^Cached:/ {print $2}' /proc/meminfo) / 1024))
  CUR_NR_FILE=$(awk '/nr_file_pages/ {print $2}' /proc/vmstat)

  ELAPSED=$(($(date +%s) - START_TIME))
  printf "    %3ds | %12s | %13s | %9s | %13s\n" "$ELAPSED" "$QUEUED" "$DEDUPED" "$CUR_CACHED" "$CUR_NR_FILE"

  if [ "$QUEUED" = "0" ] && [ "$ELAPSED" -ge 2 ]; then
    break
  fi
  if [ "$ELAPSED" -ge 60 ]; then
    echo "    Timeout reached."
    break
  fi
  sleep 1
done

echo "[9] Gathering final stats..."
kill $SAR_PID 2>/dev/null || true
wait $SAR_PID 2>/dev/null || true

NR_FILE_AFTER=$(awk '/nr_file_pages/ {print $2}' /proc/vmstat)
CACHED_AFTER=$(awk '/^Cached:/ {print $2}' /proc/meminfo)
SAVED_MB=$(((CACHED_LOADED - CACHED_AFTER) / 1024))

echo ""
echo "=========================================================="
echo "                        RESULTS"
echo "=========================================================="
echo "Memory Cached:"
echo "  Before load:   $CACHED_BEFORE KB"
echo "  After load:    $CACHED_LOADED KB (+ $LOADED_MB MB)"
echo "  After dedup:   $CACHED_AFTER KB (- $SAVED_MB MB)"
echo ""
echo "nr_file_pages:"
echo "  Before load:   $NR_FILE_BEFORE"
echo "  After load:    $NR_FILE_LOADED"
echo "  After dedup:   $NR_FILE_AFTER"

# Theoretically, if all 512MB dedups to 1 page, nr_file_pages should be NR_FILE_BEFORE + 1
EXPECTED_AFTER=$((NR_FILE_BEFORE + 1))

DIFF=$((NR_FILE_AFTER - EXPECTED_AFTER))
if [ "$DIFF" -lt 0 ]; then
  DIFF=$((-DIFF))
fi

echo ""
echo "Consistency check:"
echo "  Expected nr_file_pages after dedup: ~$EXPECTED_AFTER"
echo "  Actual nr_file_pages after dedup:    $NR_FILE_AFTER"
if [ "$DIFF" -gt 2000 ]; then
  echo "  [!] WARNING: nr_file_pages is off by $DIFF pages! Possible double accounting / leak!"
  echo "               A small deviation (few hundred) is normal due to system activity."
else
  echo "  [OK] nr_file_pages looks consistent (within expected bounds)."
fi

echo ""
echo "=========================================================="
echo "sar -r Output (every 1s during dedup):"
cat sar_output.txt | sed 's/^/  /'

echo ""
echo "Cleaning up..."
rm -f "$FILENAME" sar_output.txt
echo "Done."
