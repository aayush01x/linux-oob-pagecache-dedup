#!/bin/bash
#
# quick_test.sh — "Hello World" dedup test for Getting Started verification
#
# Creates two identical files, triggers dedup, verifies memory savings
# and COW isolation. Requires root on the custom kernel with XFS.
#
# Usage: sudo bash quick_test.sh [XFS_DIR]
#
# Human-time: ~2 min setup  |  Compute-time: ~30 seconds
#

set -e

# ── Detect XFS working directory ──────────────────────────
if [ -n "$1" ]; then
    WORKDIR="$1"
else
    XFS_MOUNT=$(findmnt -t xfs -n -o TARGET 2>/dev/null | head -1)
    WORKDIR="${XFS_MOUNT:-/tmp}"
fi

if [ ! -d "$WORKDIR" ]; then
    echo "[!] Directory $WORKDIR does not exist."
    exit 1
fi

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║    OOB Page Cache Dedup — Quick Verification Test    ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Kernel:  $(uname -r)"
echo "║  WorkDir: $WORKDIR"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

FILE_A="$WORKDIR/quick_test_a.dat"
FILE_B="$WORKDIR/quick_test_b.dat"
FILE_SIZE_MB=4
PASS=true

cleanup() {
    rm -f "$FILE_A" "$FILE_B"
}
trap cleanup EXIT

# ── Step 1: Verify kernel and sysfs ───────────────────────
echo "[1] Verifying kernel and sysfs interface..."
if [ ! -d /sys/kernel/oob_dedup ]; then
    echo "  [FAIL] /sys/kernel/oob_dedup not found. Is the custom kernel running?"
    exit 1
fi
echo "  -> Kernel: $(uname -r)"
echo "  -> pages_scanned:  $(cat /sys/kernel/oob_dedup/pages_scanned)"
echo "  -> pages_deduped:  $(cat /sys/kernel/oob_dedup/pages_deduped)"
echo "  -> files_queued:   $(cat /sys/kernel/oob_dedup/files_queued)"
echo "  -> OK"
echo ""

# ── Step 2: Create two identical files ────────────────────
echo "[2] Creating two identical ${FILE_SIZE_MB}MB files..."
dd if=/dev/zero bs=1M count=$FILE_SIZE_MB 2>/dev/null | tr '\0' 'X' > "$FILE_A"
cp "$FILE_A" "$FILE_B"
echo "  -> $FILE_A ($(stat -c%s "$FILE_A" 2>/dev/null || stat -f%z "$FILE_A") bytes)"
echo "  -> $FILE_B ($(stat -c%s "$FILE_B" 2>/dev/null || stat -f%z "$FILE_B") bytes)"
echo ""

# ── Step 3: Load into page cache and record baseline ──────
echo "[3] Loading files into page cache..."
sync && echo 3 > /proc/sys/vm/drop_caches
sleep 1
cat "$FILE_A" > /dev/null
cat "$FILE_B" > /dev/null
CACHED_BEFORE=$(awk '/^Cached:/ {print $2}' /proc/meminfo)
DEDUPED_BEFORE=$(cat /sys/kernel/oob_dedup/pages_deduped)
echo "  -> Cached (before dedup): ${CACHED_BEFORE} kB"
echo ""

# ── Step 4: Trigger dedup via posix_fadvise ───────────────
echo "[4] Triggering dedup via posix_fadvise..."
python3 -c "
import os, ctypes
libc = ctypes.CDLL('libc.so.6')
for f in ['$FILE_A', '$FILE_B']:
    fd = os.open(f, os.O_RDONLY)
    libc.posix_fadvise(fd, 0, 0, 8)
    os.close(fd)
    print(f'  [+] Queued: {os.path.basename(f)}')
"
echo ""

# ── Step 5: Wait for scanner to complete ──────────────────
echo "[5] Waiting for scanner to finish..."
TIMEOUT=30
for i in $(seq 1 $TIMEOUT); do
    QUEUED=$(cat /sys/kernel/oob_dedup/files_queued)
    if [ "$QUEUED" = "0" ]; then
        echo "  -> Scanner finished in ${i}s"
        break
    fi
    if [ "$i" = "$TIMEOUT" ]; then
        echo "  [WARN] Timeout after ${TIMEOUT}s (files_queued=$QUEUED)"
    fi
    sleep 1
done
echo ""

# ── Step 6: Check results ────────────────────────────────
echo "[6] Checking dedup results..."
CACHED_AFTER=$(awk '/^Cached:/ {print $2}' /proc/meminfo)
DEDUPED_AFTER=$(cat /sys/kernel/oob_dedup/pages_deduped)
PAGES_DEDUPED=$((DEDUPED_AFTER - DEDUPED_BEFORE))
CACHED_SAVED=$((CACHED_BEFORE - CACHED_AFTER))

echo "  -> Pages deduped this run: $PAGES_DEDUPED"
echo "  -> Cached before: ${CACHED_BEFORE} kB"
echo "  -> Cached after:  ${CACHED_AFTER} kB"
echo "  -> Memory saved:  ${CACHED_SAVED} kB"

if [ "$PAGES_DEDUPED" -gt 0 ]; then
    echo "  -> [OK] Deduplication succeeded"
else
    echo "  -> [FAIL] No pages were deduplicated!"
    PASS=false
fi
echo ""

# ── Step 7: Verify data integrity ────────────────────────
echo "[7] Verifying data integrity..."
MD5_A=$(md5sum "$FILE_A" | awk '{print $1}')
MD5_B=$(md5sum "$FILE_B" | awk '{print $1}')
echo "  -> md5 $FILE_A: $MD5_A"
echo "  -> md5 $FILE_B: $MD5_B"
if [ "$MD5_A" = "$MD5_B" ]; then
    echo "  -> [OK] Both files identical after dedup"
else
    echo "  -> [FAIL] Files differ after dedup!"
    PASS=false
fi
echo ""

# ── Step 8: Test COW isolation ───────────────────────────
echo "[8] Testing COW isolation (writing to file_b)..."
echo -n "MODIFIED" | dd of="$FILE_B" bs=1 seek=0 conv=notrunc 2>/dev/null

HEAD_A=$(head -c 8 "$FILE_A")
HEAD_B=$(head -c 8 "$FILE_B")

echo "  -> file_a head: '$HEAD_A'"
echo "  -> file_b head: '$HEAD_B'"

if [ "$HEAD_A" = "XXXXXXXX" ] && [ "$HEAD_B" = "MODIFIED" ]; then
    echo "  -> [OK] COW isolation verified — write to B did not affect A"
else
    echo "  -> [FAIL] COW isolation broken!"
    PASS=false
fi
echo ""

# ── Summary ──────────────────────────────────────────────
echo "╔══════════════════════════════════════════════════════╗"
if $PASS; then
    echo "║  [PASS] Quick verification test PASSED               ║"
else
    echo "║  [FAIL] Quick verification test FAILED               ║"
fi
echo "╚══════════════════════════════════════════════════════╝"

$PASS && exit 0 || exit 1
