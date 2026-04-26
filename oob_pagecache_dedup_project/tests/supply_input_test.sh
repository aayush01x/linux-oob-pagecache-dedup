#!/bin/bash
#
# supply_input_test.sh — Test OOB dedup with user-supplied input files
#
# Copies user-provided files to XFS, loads them into page cache,
# triggers dedup, monitors progress, and verifies data integrity.
#
# Usage: sudo bash supply_input_test.sh <file1> <file2> [file3 ...]
#
# The files should have identical (or partially identical) content.
# At least 2 files are required.
#
# Human-time: ~2 min  |  Compute-time: depends on file size
#

set -e

if [ "$#" -lt 2 ]; then
    echo "Usage: sudo bash $0 <file1> <file2> [file3 ...]"
    echo ""
    echo "Supply at least 2 files with identical content to test dedup."
    echo "Example: sudo bash $0 /path/to/data_a.bin /path/to/data_b.bin"
    exit 1
fi

# ── Detect XFS working directory ──────────────────────────
XFS_MOUNT=$(findmnt -t xfs -n -o TARGET 2>/dev/null | head -1)
WORKDIR="${XFS_MOUNT:-/tmp}/supply_input_test"
mkdir -p "$WORKDIR"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   OOB Page Cache Dedup — Custom Input Test           ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Kernel:  $(uname -r)"
echo "║  WorkDir: $WORKDIR"
echo "║  Files:   $#"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# Verify sysfs
if [ ! -d /sys/kernel/oob_dedup ]; then
    echo "[FAIL] /sys/kernel/oob_dedup not found. Is the custom kernel running?"
    exit 1
fi

# ── Step 1: Copy files to XFS ────────────────────────────
echo "[1] Copying files to XFS working directory..."
COPIED=()
IDX=1
for SRC in "$@"; do
    if [ ! -f "$SRC" ]; then
        echo "  [WARN] $SRC does not exist, skipping."
        continue
    fi
    BASENAME="input_${IDX}_$(basename "$SRC")"
    DST="$WORKDIR/$BASENAME"
    cp "$SRC" "$DST"
    COPIED+=("$DST")
    SIZE_KB=$(( $(stat -c%s "$DST" 2>/dev/null || stat -f%z "$DST") / 1024 ))
    echo "  -> Copied: $BASENAME (${SIZE_KB} KB)"
    IDX=$((IDX + 1))
done

if [ "${#COPIED[@]}" -lt 2 ]; then
    echo "[FAIL] Need at least 2 valid files."
    rm -rf "$WORKDIR"
    exit 1
fi
echo ""

cleanup() {
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# ── Step 2: Record checksums before dedup ────────────────
echo "[2] Recording pre-dedup checksums..."
declare -A CHECKSUMS
for F in "${COPIED[@]}"; do
    MD5=$(md5sum "$F" | awk '{print $1}')
    CHECKSUMS["$F"]="$MD5"
    echo "  -> $(basename "$F"): $MD5"
done
echo ""

# ── Step 3: Load into page cache ─────────────────────────
echo "[3] Loading files into page cache..."
sync && echo 3 > /proc/sys/vm/drop_caches
sleep 1
for F in "${COPIED[@]}"; do
    cat "$F" > /dev/null
done
CACHED_BEFORE=$(awk '/^Cached:/ {print $2}' /proc/meminfo)
DEDUPED_BEFORE=$(cat /sys/kernel/oob_dedup/pages_deduped)
echo "  -> Cached: ${CACHED_BEFORE} kB"
echo ""

# ── Step 4: Trigger dedup ────────────────────────────────
echo "[4] Queueing files for dedup..."
FADVISE_LIST=""
for F in "${COPIED[@]}"; do
    FADVISE_LIST="$FADVISE_LIST '$F',"
done

python3 -c "
import os, ctypes
libc = ctypes.CDLL('libc.so.6')
for f in [${FADVISE_LIST}]:
    fd = os.open(f, os.O_RDONLY)
    libc.posix_fadvise(fd, 0, 0, 8)
    os.close(fd)
    print(f'  [+] Queued: {os.path.basename(f)}')
"
echo ""

# ── Step 5: Monitor progress ────────────────────────────
echo "[5] Monitoring dedup progress (up to 120s)..."
echo "    ┌─────────┬────────────┬──────────────┬──────────┐"
echo "    │  Time   │  Deduped   │   Cached     │  Queued  │"
echo "    ├─────────┼────────────┼──────────────┼──────────┤"
TIMEOUT=120
for i in $(seq 1 $TIMEOUT); do
    QUEUED=$(cat /sys/kernel/oob_dedup/files_queued)
    DEDUPED_NOW=$(cat /sys/kernel/oob_dedup/pages_deduped)
    DELTA=$((DEDUPED_NOW - DEDUPED_BEFORE))
    CACHED_NOW=$(awk '/^Cached:/ {print $2}' /proc/meminfo)
    CACHED_MB=$((CACHED_NOW / 1024))
    printf "    │  %3ds   │  %8d  │  %6d MB  │  %5d   │\n" "$i" "$DELTA" "$CACHED_MB" "$QUEUED"
    if [ "$QUEUED" = "0" ] && [ "$i" -ge 3 ]; then
        break
    fi
    sleep 1
done
echo "    └─────────┴────────────┴──────────────┴──────────┘"
echo ""

# ── Step 6: Results ──────────────────────────────────────
CACHED_AFTER=$(awk '/^Cached:/ {print $2}' /proc/meminfo)
DEDUPED_AFTER=$(cat /sys/kernel/oob_dedup/pages_deduped)
PAGES_DEDUPED=$((DEDUPED_AFTER - DEDUPED_BEFORE))
CACHED_SAVED=$((CACHED_BEFORE - CACHED_AFTER))
SAVED_MB=$((CACHED_SAVED / 1024))

echo "[6] Results:"
echo "  -> Pages deduped:  $PAGES_DEDUPED"
echo "  -> Memory saved:   ${CACHED_SAVED} kB (~${SAVED_MB} MB)"
echo ""

# ── Step 7: Verify data integrity ────────────────────────
echo "[7] Verifying data integrity (checksums must match)..."
INTEGRITY_OK=true
for F in "${COPIED[@]}"; do
    MD5_NOW=$(md5sum "$F" | awk '{print $1}')
    MD5_ORIG="${CHECKSUMS[$F]}"
    if [ "$MD5_NOW" = "$MD5_ORIG" ]; then
        echo "  -> $(basename "$F"): OK (checksum matches)"
    else
        echo "  -> $(basename "$F"): FAIL (checksum changed!)"
        echo "     Before: $MD5_ORIG"
        echo "     After:  $MD5_NOW"
        INTEGRITY_OK=false
    fi
done
echo ""

# ── Summary ──────────────────────────────────────────────
echo "╔══════════════════════════════════════════════════════╗"
if $INTEGRITY_OK && [ "$PAGES_DEDUPED" -gt 0 ]; then
    echo "║  [PASS] Custom input test PASSED                     ║"
    echo "║  Data integrity verified, dedup successful           ║"
elif $INTEGRITY_OK; then
    echo "║  [WARN] No pages deduped (files may not be identical)║"
    echo "║  Data integrity verified                             ║"
else
    echo "║  [FAIL] Data integrity check FAILED                  ║"
fi
echo "╚══════════════════════════════════════════════════════╝"

$INTEGRITY_OK && exit 0 || exit 1
