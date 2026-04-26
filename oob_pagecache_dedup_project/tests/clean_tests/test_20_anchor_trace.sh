#!/bin/bash
#
# test_anchor_hashing.sh
#
# Standalone test script for anchor-based hashing.
# Runs the C test, then greps dmesg for anchor trace messages.
# Must be run as root, from the clean_tests/ directory.
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Find XFS mount for large folio support
XFS_MOUNT=$(findmnt -t xfs -n -o TARGET 2>/dev/null | head -1)
TEST_WORKDIR="${XFS_MOUNT:-$SCRIPT_DIR}"

if [ ! -d "$TEST_WORKDIR" ]; then
    echo "[!] $TEST_WORKDIR does not exist. Using script directory."
    TEST_WORKDIR="$SCRIPT_DIR"
fi

echo "========================================================"
echo "  Anchor-Based Hashing — Full Verification"
echo "========================================================"
echo "[*] Working dir: $TEST_WORKDIR"
echo ""

# --- 1. Compile -----------------------------------------------------------
echo "[*] Compiling test_16_anchor_partial_match.c..."
gcc -Wall -Wextra -O2 -o "$TEST_WORKDIR/test_16_anchor_partial_match" \
    "$SCRIPT_DIR/test_16_anchor_partial_match.c" \
    "$SCRIPT_DIR/common.c"
echo "  -> OK"
echo ""

# --- 2. Clear dmesg to get clean anchor logs ------------------------------
echo "[*] Clearing dmesg..."
dmesg -C
echo "  -> OK"
echo ""

# --- 3. Show current sysfs stats (before) ---------------------------------
echo "[*] Sysfs stats BEFORE test:"
echo "  pages_scanned : $(cat /sys/kernel/oob_dedup/pages_scanned 2>/dev/null || echo N/A)"
echo "  pages_deduped : $(cat /sys/kernel/oob_dedup/pages_deduped 2>/dev/null || echo N/A)"
echo "  folios_split  : $(cat /sys/kernel/oob_dedup/folios_split 2>/dev/null || echo N/A)"
echo "  files_queued  : $(cat /sys/kernel/oob_dedup/files_queued 2>/dev/null || echo N/A)"
echo ""

# --- 4. Run the test -------------------------------------------------------
echo "[*] Running test..."
cd "$TEST_WORKDIR"
RESULT=0
sudo ./test_16_anchor_partial_match || RESULT=$?
cd "$SCRIPT_DIR"
echo ""

# --- 5. Show sysfs stats (after) ------------------------------------------
echo "[*] Sysfs stats AFTER test:"
echo "  pages_scanned : $(cat /sys/kernel/oob_dedup/pages_scanned 2>/dev/null || echo N/A)"
echo "  pages_deduped : $(cat /sys/kernel/oob_dedup/pages_deduped 2>/dev/null || echo N/A)"
echo "  folios_split  : $(cat /sys/kernel/oob_dedup/folios_split 2>/dev/null || echo N/A)"
echo "  files_queued  : $(cat /sys/kernel/oob_dedup/files_queued 2>/dev/null || echo N/A)"
echo ""

# --- 6. Extract and display anchor trace from dmesg -----------------------
echo "========================================================"
echo "  ANCHOR TRACE FROM dmesg"
echo "========================================================"
echo ""

echo "--- Phase 1: I/O Veto (dirty/writeback skips) ---"
dmesg | grep -c "\\[VETO\\]" && echo " veto events found" || echo "  (none — good, means folios were clean)"
dmesg | grep "\\[VETO\\]" | head -5
echo ""

echo "--- Phase 2: Zero-page short circuit ---"
dmesg | grep -c "\\[ZERO\\]" && echo " zero-page skips found" || echo "  (none — expected for non-sparse files)"
dmesg | grep "\\[ZERO\\]" | head -5
echo ""

echo "--- Phase 3: Anchor Geometry (large folios) ---"
dmesg | grep "\\[ANCHOR\\] large folio" | head -10
echo ""

echo "--- Anchor Hash Values ---"
dmesg | grep "\\[ANCHOR\\]   anchor" | head -20
echo ""

echo "--- Anchor Table Lookups ---"
dmesg | grep "\\[ANCHOR\\] searching" | head -10
echo ""

echo "--- Anchor HIT Events (partial/full compare) ---"
HITS=$(dmesg | grep "\\[ANCHOR\\].*HIT" | wc -l)
echo "  Total anchor hits: $HITS"
dmesg | grep "\\[ANCHOR\\].*HIT" | head -10
echo ""

echo "--- Partial Match Splits ---"
SPLITS=$(dmesg | grep "Partial match.*Splitting" | wc -l)
echo "  Total partial match splits: $SPLITS"
dmesg | grep "Partial match.*Splitting" | head -10
echo ""

echo "--- Exact Duplicate Merges ---"
MERGES=$(dmesg | grep "Exact duplicate verified" | wc -l)
echo "  Total exact merges: $MERGES"
dmesg | grep "Exact duplicate verified" | head -10
echo ""

echo "--- Hash Table Stores ---"
dmesg | grep "\\[ANCHOR\\] no match.*storing" | head -10
echo ""

# --- 7. Verify expected behavior ------------------------------------------
echo "========================================================"
echo "  EXPECTED BEHAVIOR CHECK"
echo "========================================================"

ANCHOR_GEOS=$(dmesg | grep -c "\\[ANCHOR\\] large folio" || true)
ORDER0_ANCHORS=$(dmesg | grep -c "\\[ANCHOR\\] order-0" || true)

if [ "$ANCHOR_GEOS" -gt 0 ]; then
    echo "  [OK] Large folio anchor geometry computed: $ANCHOR_GEOS times"
else
    echo "  [??] No large folio anchor geometry found."
    echo "       This is OK if XFS split folios to order-0 before scanning."
    echo "       Check if order-0 anchors were used instead."
fi

if [ "$ORDER0_ANCHORS" -gt 0 ]; then
    echo "  [OK] Order-0 anchor hashing used: $ORDER0_ANCHORS times"
fi

if [ "$HITS" -gt 0 ]; then
    echo "  [OK] Anchor hash table hits: $HITS"
else
    echo "  [WARN] No anchor hits. Files may not have been in page cache simultaneously."
fi

if [ "$MERGES" -gt 0 ]; then
    echo "  [OK] Exact dedup merges: $MERGES"
else
    echo "  [WARN] No exact merges occurred."
fi

echo ""

# --- 8. Cleanup ------------------------------------------------------------
rm -f "$TEST_WORKDIR/test_16_anchor_partial_match"
rm -f "$TEST_WORKDIR/anchor_partial_a.dat" "$TEST_WORKDIR/anchor_partial_b.dat"

# --- 9. Save full dmesg log ------------------------------------------------
LOGFILE="$SCRIPT_DIR/dmesg_anchor_trace.log"
dmesg | grep "OOB_DEDUP" > "$LOGFILE"
echo "[*] Full OOB_DEDUP dmesg saved to: $LOGFILE"
echo ""

if [ "$RESULT" -eq 0 ]; then
    echo "========================================================"
    echo "  [PASS] Anchor hashing test completed successfully"
    echo "========================================================"
else
    echo "========================================================"
    echo "  [FAIL] Anchor hashing test FAILED (exit code $RESULT)"
    echo "========================================================"
fi

exit $RESULT
