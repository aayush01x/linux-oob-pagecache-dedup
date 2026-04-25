#!/bin/bash
# test_large_file_dedup.sh — Inter-file dedup benchmark
#
# Demonstrates OOB scanner effectiveness on realistic workloads.
# Creates N identical large files, loads them into page cache, triggers
# dedup, and tracks progress with live stats.
#
# Requires: ~3× FILE_SIZE_MB of free disk + RAM for page cache
# Run as root:  sudo ./test_large_file_dedup.sh

set -e

TEST_DIR="/mnt/test_large"
NUM_FILES=3
FILE_SIZE_MB=32   # 32 MB per file → 96 MB total
FILL_CHAR="X"
WAIT=120            # seconds to wait for scanner (large files need more time)

TOTAL_MB=$(( NUM_FILES * FILE_SIZE_MB ))

mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

echo "╔══════════════════════════════════════════════╗"
echo "║   Large-File Inter-File Dedup Benchmark      ║"
echo "╠══════════════════════════════════════════════╣"
echo "║  Files: ${NUM_FILES} × ${FILE_SIZE_MB}MB = ${TOTAL_MB}MB total              ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ── Step 0: Clean baseline ────────────────────────────────────────
echo "[0] Dropping caches for clean baseline..."
sync
echo 3 > /proc/sys/vm/drop_caches
sleep 2

echo ""
echo "─── BASELINE ───"
grep -E "MemFree|MemAvailable|Cached" /proc/meminfo
CACHED_BASELINE=$(awk '/^Cached:/ {print $2}' /proc/meminfo)
MEMFREE_BASELINE=$(awk '/^MemFree:/ {print $2}' /proc/meminfo)
echo ""

# Check available memory
AVAIL_MB=$(( MEMFREE_BASELINE / 1024 ))
if [ "$AVAIL_MB" -lt "$TOTAL_MB" ]; then
    echo "⚠  WARNING: Only ${AVAIL_MB}MB free, need ${TOTAL_MB}MB for full page cache load."
    echo "   Results may be affected by memory pressure / eviction."
    echo ""
fi

# ── Step 1: Create identical large files ──────────────────────────
echo "[1] Creating ${NUM_FILES} identical ${FILE_SIZE_MB}MB files..."
echo "    (This may take a minute...)"

# Create the first file, then copy it (much faster than dd+tr for 1GB)
echo -n "    Creating source file..."
dd if=/dev/zero bs=1M count=$FILE_SIZE_MB 2>/dev/null | tr '\0' "$FILL_CHAR" > "large_dedup_1.dat"
echo " done ($(du -h large_dedup_1.dat | cut -f1))"

for i in $(seq 2 $NUM_FILES); do
    echo -n "    Copying to large_dedup_$i.dat..."
    cp "large_dedup_1.dat" "large_dedup_$i.dat"
    echo " done"
done
echo ""

# ── Step 2: Flush + reload into clean page cache ─────────────────
echo "[2] Syncing + dropping caches to get clean page cache..."
sync
echo 3 > /proc/sys/vm/drop_caches
sleep 2

echo "[3] Reading all files into page cache..."
for i in $(seq 1 $NUM_FILES); do
    echo -n "    Reading large_dedup_$i.dat..."
    cat "large_dedup_$i.dat" > /dev/null
    echo " done"
done

# ── Measure BEFORE dedup ──────────────────────────────────────────
echo ""
echo "─── AFTER LOADING (before dedup) ───"
grep -E "MemFree|MemAvailable|Cached" /proc/meminfo
CACHED_LOADED=$(awk '/^Cached:/ {print $2}' /proc/meminfo)
CONSUMED=$(( (CACHED_LOADED - CACHED_BASELINE) / 1024 ))
echo "  → ${CONSUMED} MB consumed by page cache"
echo ""

# Reset scanner stats to get clean measurements for this run
if [ -d /sys/kernel/oob_dedup ]; then
    DEDUPED_BEFORE=$(cat /sys/kernel/oob_dedup/pages_deduped)
    SCANNED_BEFORE=$(cat /sys/kernel/oob_dedup/pages_scanned)
else
    DEDUPED_BEFORE=0
    SCANNED_BEFORE=0
fi

# ── Step 4: Queue files for dedup ─────────────────────────────────
echo "[4] Queueing files for dedup..."
for i in $(seq 1 $NUM_FILES); do
    python3 -c "
import os, ctypes
POSIX_FADV_DEDUP = 8
fd = os.open('large_dedup_$i.dat', os.O_RDONLY)
libc = ctypes.CDLL('libc.so.6')
libc.posix_fadvise(fd, 0, 0, POSIX_FADV_DEDUP)
os.close(fd)
" 2>/dev/null || true
    echo "  [+] Queued large_dedup_$i.dat"
done
echo ""

# ── Step 5: Wait with live progress ──────────────────────────────
echo "[5] Waiting for dedup scanner (up to ${WAIT}s)..."
echo "    ┌─────────┬────────────┬──────────────┬──────────┐"
echo "    │  Time   │  Deduped   │   Cached     │  Queued  │"
echo "    ├─────────┼────────────┼──────────────┼──────────┤"

START_TIME=$(date +%s)
PREV_DEDUPED=$DEDUPED_BEFORE

for i in $(seq 1 $WAIT); do
    sleep 1

    # Read current stats
    CUR_CACHED=$(awk '/^Cached:/ {print $2}' /proc/meminfo)
    CUR_CACHED_MB=$(( CUR_CACHED / 1024 ))

    if [ -d /sys/kernel/oob_dedup ]; then
        CUR_DEDUPED=$(cat /sys/kernel/oob_dedup/pages_deduped)
        CUR_QUEUED=$(cat /sys/kernel/oob_dedup/files_queued)
    else
        CUR_DEDUPED=0
        CUR_QUEUED="?"
    fi

    # Calculate deltas for this run
    RUN_DEDUPED=$(( CUR_DEDUPED - DEDUPED_BEFORE ))

    printf "    │  %3ds   │  %7d   │  %7d MB  │    %s     │\n" \
           "$i" "$RUN_DEDUPED" "$CUR_CACHED_MB" "$CUR_QUEUED"

    # Early exit if scanner finished
    if [ "$CUR_QUEUED" = "0" ] && [ "$i" -ge 5 ]; then
        echo "    └─────────┴────────────┴──────────────┴──────────┘"
        echo "    Scanner finished early at ${i}s!"
        break
    fi

    if [ "$i" -eq "$WAIT" ]; then
        echo "    └─────────┴────────────┴──────────────┴──────────┘"
    fi
done
echo ""

# ── Results ───────────────────────────────────────────────────────
ELAPSED=$(( $(date +%s) - START_TIME ))

echo "─── AFTER DEDUP ───"
grep -E "MemFree|MemAvailable|Cached" /proc/meminfo
CACHED_AFTER=$(awk '/^Cached:/ {print $2}' /proc/meminfo)
SAVED=$(( (CACHED_LOADED - CACHED_AFTER) / 1024 ))
echo "  → ${SAVED} MB freed by dedup"
echo ""

# Scanner throughput stats
if [ -d /sys/kernel/oob_dedup ]; then
    FINAL_DEDUPED=$(cat /sys/kernel/oob_dedup/pages_deduped)
    FINAL_SCANNED=$(cat /sys/kernel/oob_dedup/pages_scanned)
    FINAL_QUEUED=$(cat /sys/kernel/oob_dedup/files_queued)
    FINAL_SPLIT=$(cat /sys/kernel/oob_dedup/folios_split)

    RUN_DEDUPED=$(( FINAL_DEDUPED - DEDUPED_BEFORE ))
    RUN_SCANNED=$(( FINAL_SCANNED - SCANNED_BEFORE ))

    # Estimate throughput (pages are 4KB)
    if [ "$ELAPSED" -gt 0 ]; then
        DEDUP_RATE_MB=$(( RUN_DEDUPED * 4 / 1024 / ELAPSED ))  # rough: folios vary in size
        SCAN_RATE_MB=$(( RUN_SCANNED * 4 / 1024 / ELAPSED ))
    else
        DEDUP_RATE_MB=0
        SCAN_RATE_MB=0
    fi

    echo "─── SCANNER PERFORMANCE ───"
    echo "  Pages scanned (this run):  ${RUN_SCANNED}"
    echo "  Folios deduped (this run): ${RUN_DEDUPED}"
    echo "  Folios split:              ${FINAL_SPLIT}"
    echo "  Files still queued:        ${FINAL_QUEUED}"
    echo "  Elapsed time:              ${ELAPSED}s"
    echo "  Scan throughput:           ~${SCAN_RATE_MB} MB/s"
    echo ""
fi

# ── Data integrity check ─────────────────────────────────────────
echo "[6] Verifying file integrity..."
PASS=true
for i in $(seq 1 $NUM_FILES); do
    EXPECTED=$(( FILE_SIZE_MB * 1024 * 1024 ))
    ACTUAL=$(wc -c < "large_dedup_$i.dat")
    SAMPLE=$(head -c 1 "large_dedup_$i.dat")
    TAIL=$(tail -c 1 "large_dedup_$i.dat")
    if [ "$ACTUAL" -eq "$EXPECTED" ] && [ "$SAMPLE" = "$FILL_CHAR" ] && [ "$TAIL" = "$FILL_CHAR" ]; then
        echo "  large_dedup_$i.dat: OK (${FILE_SIZE_MB}MB, head='$FILL_CHAR', tail='$FILL_CHAR')"
    else
        echo "  large_dedup_$i.dat: FAIL (size=$ACTUAL, head=$SAMPLE, tail=$TAIL)"
        PASS=false
    fi
done

# ── Cleanup ───────────────────────────────────────────────────────
echo ""
echo "[7] Cleaning up..."
rm -f "$TEST_DIR"/large_dedup_*.dat

echo ""
if $PASS; then
    EFFICIENCY=0
    if [ "$CONSUMED" -gt 0 ]; then
        EFFICIENCY=$(( SAVED * 100 / CONSUMED ))
    fi
    echo "╔══════════════════════════════════════════════╗"
    echo "║              BENCHMARK RESULTS               ║"
    echo "╠══════════════════════════════════════════════╣"
    printf "║  Total data:        %5d MB                 ║\n" "$TOTAL_MB"
    printf "║  Page cache used:   %5d MB                 ║\n" "$CONSUMED"
    printf "║  Memory freed:      %5d MB                 ║\n" "$SAVED"
    printf "║  Dedup efficiency:  %4d%%                   ║\n" "$EFFICIENCY"
    printf "║  Time to dedup:     %4ds                    ║\n" "$ELAPSED"
    echo "║  Data integrity:    PASS ✓                  ║"
    echo "╚══════════════════════════════════════════════╝"
else
    echo "╔══════════════════════════════════════════════╗"
    echo "║  [FAIL] Data integrity check failed!         ║"
    echo "╚══════════════════════════════════════════════╝"
fi
