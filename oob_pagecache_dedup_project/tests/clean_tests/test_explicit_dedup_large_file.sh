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

FILE_SIZE_MB=200
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

# After intra-file dedup, all identical pages collapse to 1 folio.
# nr_file_pages should drop by roughly (loaded_pages - 1_folio).
# We compare the DELTA rather than absolute value, since baseline
# pages may be evicted by LRU during the 200MB load.
NR_LOADED=$((NR_FILE_LOADED - NR_FILE_BEFORE))
NR_FREED=$((NR_FILE_LOADED - NR_FILE_AFTER))

echo ""
echo "Dedup efficiency:"
echo "  Pages loaded into cache:  $NR_LOADED"
echo "  Pages freed by dedup:     $NR_FREED"

# On loopback, only ~half the loaded pages are from the XFS layer
# (the other half is the ext4 cache of the .img file, untouchable).
# On native XFS, nearly all loaded pages should be freed.
if [ "$NR_LOADED" -gt 0 ]; then
  EFFICIENCY=$((NR_FREED * 100 / NR_LOADED))
  echo "  Efficiency:               ${EFFICIENCY}%"
  if [ "$EFFICIENCY" -ge 30 ]; then
    echo "  [OK] Dedup freed a significant portion of cached pages."
  else
    echo "  [!] WARNING: Low dedup efficiency. Check if pages were evicted or not deduped."
  fi
else
  echo "  [!] No pages loaded? Something is wrong."
fi

echo ""
echo "=========================================================="
echo "sar -r Output (every 1s during dedup):"
cat sar_output.txt | sed 's/^/  /'

echo ""
echo "Cleaning up..."
rm -f "$FILENAME" sar_output.txt
echo "Done."
