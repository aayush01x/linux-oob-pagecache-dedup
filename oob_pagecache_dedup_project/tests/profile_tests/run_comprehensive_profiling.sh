#!/bin/bash
# run_comprehensive_profiling.sh — Master profiling suite for OOB page-cache dedup
# Must be run as root on the custom kernel.
# Generates: results/ directory with JSON data + PNG graphs + markdown report
#
# Usage: sudo bash run_comprehensive_profiling.sh [TEST_DIR]

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Auto-detect XFS, override with $1 or TEST_DIR env
if [ -n "$1" ]; then
    BASE_DIR="$1"
elif [ -n "$TEST_DIR" ]; then
    BASE_DIR="$TEST_DIR"
else
    XFS_MOUNT=$(findmnt -t xfs -n -o TARGET 2>/dev/null | head -1)
    BASE_DIR="${XFS_MOUNT:-/tmp}/dedup_profiling"
fi

RESULTS_DIR="$SCRIPT_DIR/results"
WORK_DIR="$BASE_DIR/work"
BENCH="$WORK_DIR/profile_bench"

mkdir -p "$RESULTS_DIR" "$WORK_DIR"

# Compile bench helper
echo "[*] Compiling profile_bench.c..."
gcc -O2 -pthread -o "$BENCH" "$SCRIPT_DIR/profile_bench.c"

# ─── Helpers ───────────────────────────────────────────────
drop_caches() { sync; echo 3 > /proc/sys/vm/drop_caches; sleep 1; }

sysfs_val() { cat "/sys/kernel/oob_dedup/$1" 2>/dev/null || echo 0; }

ts() { date '+%Y-%m-%d %H:%M:%S'; }

log() { echo "[$(ts)] $*"; }

create_file() { # path size_mb fill_char
    dd if=/dev/zero bs=1M count="$2" 2>/dev/null | tr '\0' "$3" > "$1"
}

cached_kb() { awk '/^Cached:/ {print $2}' /proc/meminfo; }

# ─── Experiment 1: Memory Savings vs File Count ───────────
run_exp1_memory_savings() {
    log "=== EXP 1: Memory Savings vs File Count ==="
    local FILE_MB=16
    local OUT="$RESULTS_DIR/exp1_memory_savings.csv"
    echo "num_files,total_mb,cached_before_kb,cached_after_load_kb,cached_after_dedup_kb,saved_kb,pages_deduped,time_s" > "$OUT"

    for N in 2 4 8 16; do
        log "  N=$N files x ${FILE_MB}MB..."
        drop_caches
        local C_BASE=$(cached_kb)

        # Create files
        create_file "$WORK_DIR/src.dat" "$FILE_MB" "A"
        for i in $(seq 1 $N); do cp "$WORK_DIR/src.dat" "$WORK_DIR/mf_$i.dat"; done
        rm -f "$WORK_DIR/src.dat"

        # Load into page cache
        drop_caches; sleep 1
        for i in $(seq 1 $N); do cat "$WORK_DIR/mf_$i.dat" > /dev/null; done
        local C_LOADED=$(cached_kb)

        # Dedup
        local D_BEFORE=$(sysfs_val pages_deduped)
        local T0=$(date +%s)
        local FILES=""
        for i in $(seq 1 $N); do FILES="$FILES $WORK_DIR/mf_$i.dat"; done
        "$BENCH" --dedup $FILES > /dev/null 2>&1
        local T1=$(date +%s)
        local D_AFTER=$(sysfs_val pages_deduped)
        local C_DEDUP=$(cached_kb)

        local SAVED=$(( C_LOADED - C_DEDUP ))
        local ELAPSED=$(( T1 - T0 ))
        local PD=$(( D_AFTER - D_BEFORE ))
        echo "$N,$((N*FILE_MB)),$C_BASE,$C_LOADED,$C_DEDUP,$SAVED,$PD,$ELAPSED" >> "$OUT"

        drop_caches
        rm -f "$WORK_DIR"/mf_*.dat
    done
    log "  -> $OUT"
}

# ─── Experiment 2: Scanner Throughput vs File Size ────────
run_exp2_scan_throughput() {
    log "=== EXP 2: Scanner Throughput vs File Size ==="
    local OUT="$RESULTS_DIR/exp2_scan_throughput.csv"
    echo "size_mb,dedup_time_ns,pages_scanned,pages_deduped,scan_rate_pages_per_sec" > "$OUT"

    for SZ in 4 8 16 32 64; do
        log "  size=${SZ}MB..."
        drop_caches
        create_file "$WORK_DIR/st_a.dat" "$SZ" "B"
        cp "$WORK_DIR/st_a.dat" "$WORK_DIR/st_b.dat"
        drop_caches
        cat "$WORK_DIR/st_a.dat" > /dev/null
        cat "$WORK_DIR/st_b.dat" > /dev/null

        local RAW=$("$BENCH" --dedup "$WORK_DIR/st_a.dat" "$WORK_DIR/st_b.dat")
        local DNS=$(echo "$RAW" | awk -F': ' '/dedup_time_ns/{print $2}')
        local PS=$(echo "$RAW" | awk -F': ' '/pages_scanned_delta/{print $2}')
        local PD=$(echo "$RAW" | awk -F': ' '/pages_deduped_delta/{print $2}')
        local RATE=0
        if [ "$DNS" -gt 0 ] 2>/dev/null; then
            RATE=$(python3 -c "print(int($PS / ($DNS / 1e9)))" 2>/dev/null || echo 0)
        fi
        echo "$SZ,$DNS,$PS,$PD,$RATE" >> "$OUT"

        drop_caches
        rm -f "$WORK_DIR"/st_*.dat
    done
    log "  -> $OUT"
}

# ─── Experiment 4: Write/COW Latency ─────────────────────
run_exp4_write_latency() {
    log "=== EXP 4: Write Latency — Normal vs COW ==="
    local OUT="$RESULTS_DIR/exp4_write_latency.csv"
    echo "size_mb,normal_write_ns,normal_write_mbps,cow_full_write_ns,cow_full_write_mbps,cow_single_page_ns" > "$OUT"

    for SZ in 4 8 16 32; do
        log "  size=${SZ}MB..."
        create_file "$WORK_DIR/wl_norm.dat" "$SZ" "N"
        create_file "$WORK_DIR/wl_a.dat" "$SZ" "D"
        cp "$WORK_DIR/wl_a.dat" "$WORK_DIR/wl_b.dat"
        create_file "$WORK_DIR/wl_cow1.dat" "$SZ" "D"
        cp "$WORK_DIR/wl_cow1.dat" "$WORK_DIR/wl_cow1_sib.dat"

        # Normal write
        drop_caches
        cat "$WORK_DIR/wl_norm.dat" > /dev/null
        local NW=$("$BENCH" --write "$WORK_DIR/wl_norm.dat")
        local NW_NS=$(echo "$NW" | awk -F': ' '/write_time_ns/{print $2}')
        local NW_MBPS=$(echo "$NW" | awk -F': ' '/write_throughput_mbps/{print $2}')

        # Dedup then full overwrite (COW every page)
        drop_caches
        cat "$WORK_DIR/wl_a.dat" > /dev/null
        cat "$WORK_DIR/wl_b.dat" > /dev/null
        "$BENCH" --dedup "$WORK_DIR/wl_a.dat" "$WORK_DIR/wl_b.dat" > /dev/null 2>&1
        local CW=$("$BENCH" --write "$WORK_DIR/wl_b.dat")
        local CW_NS=$(echo "$CW" | awk -F': ' '/write_time_ns/{print $2}')
        local CW_MBPS=$(echo "$CW" | awk -F': ' '/write_throughput_mbps/{print $2}')

        # Single-page COW
        drop_caches
        cat "$WORK_DIR/wl_cow1.dat" > /dev/null
        cat "$WORK_DIR/wl_cow1_sib.dat" > /dev/null
        "$BENCH" --dedup "$WORK_DIR/wl_cow1.dat" "$WORK_DIR/wl_cow1_sib.dat" > /dev/null 2>&1
        local SC=$("$BENCH" --cow-write "$WORK_DIR/wl_cow1_sib.dat")
        local SC_NS=$(echo "$SC" | awk -F': ' '/cow_write_time_ns/{print $2}')

        echo "$SZ,$NW_NS,$NW_MBPS,$CW_NS,$CW_MBPS,$SC_NS" >> "$OUT"

        drop_caches
        rm -f "$WORK_DIR"/wl_*.dat
    done
    log "  -> $OUT"
}

# ─── Experiment 5: Scalability (Fanout) ──────────────────
run_exp5_fanout_scalability() {
    log "=== EXP 5: Fanout Scalability ==="
    local FILE_MB=8
    local OUT="$RESULTS_DIR/exp5_fanout_scalability.csv"
    echo "num_copies,dedup_time_ns,pages_deduped,memory_saved_kb" > "$OUT"

    for N in 2 4 8 16 32; do
        log "  fanout=$N..."
        drop_caches
        create_file "$WORK_DIR/fan_src.dat" "$FILE_MB" "F"
        local FILES="$WORK_DIR/fan_src.dat"
        for i in $(seq 2 $N); do
            cp "$WORK_DIR/fan_src.dat" "$WORK_DIR/fan_$i.dat"
            FILES="$FILES $WORK_DIR/fan_$i.dat"
        done

        drop_caches
        for f in $FILES; do cat "$f" > /dev/null; done
        local C_PRE=$(cached_kb)

        local RAW=$("$BENCH" --dedup $FILES)
        local DNS=$(echo "$RAW" | awk -F': ' '/dedup_time_ns/{print $2}')
        local PD=$(echo "$RAW" | awk -F': ' '/pages_deduped_delta/{print $2}')
        local C_POST=$(cached_kb)
        local SAVED=$(( C_PRE - C_POST ))

        echo "$N,$DNS,$PD,$SAVED" >> "$OUT"

        drop_caches
        rm -f "$WORK_DIR"/fan_*.dat
    done
    log "  -> $OUT"
}

# ─── Experiment 6: Scanner Sysfs Live Trace ──────────────
run_exp6_live_trace() {
    log "=== EXP 6: Scanner Live Trace (32MB x 4 files) ==="
    local FILE_MB=32
    local N=4
    local OUT="$RESULTS_DIR/exp6_live_trace.csv"
    echo "time_s,pages_scanned,pages_deduped,files_queued,cached_kb" > "$OUT"

    create_file "$WORK_DIR/lt_src.dat" "$FILE_MB" "T"
    for i in $(seq 2 $N); do cp "$WORK_DIR/lt_src.dat" "$WORK_DIR/lt_$i.dat"; done

    drop_caches
    for i in $(seq 1 $N); do
        local F="$WORK_DIR/lt_src.dat"
        [ "$i" -gt 1 ] && F="$WORK_DIR/lt_$i.dat"
        cat "$F" > /dev/null
    done

    local SC0=$(sysfs_val pages_scanned)
    local PD0=$(sysfs_val pages_deduped)

    # Queue files
    local FILES="$WORK_DIR/lt_src.dat"
    for i in $(seq 2 $N); do FILES="$FILES $WORK_DIR/lt_$i.dat"; done
    for F in $FILES; do
        python3 -c "
import os, ctypes
fd = os.open('$F', os.O_RDONLY)
ctypes.CDLL('libc.so.6').posix_fadvise(fd, 0, 0, 8)
os.close(fd)
" 2>/dev/null
    done

    # Sample every second
    for S in $(seq 0 60); do
        local SC=$(( $(sysfs_val pages_scanned) - SC0 ))
        local PD=$(( $(sysfs_val pages_deduped) - PD0 ))
        local FQ=$(sysfs_val files_queued)
        local CK=$(cached_kb)
        echo "$S,$SC,$PD,$FQ,$CK" >> "$OUT"
        [ "$FQ" = "0" ] && [ "$S" -ge 3 ] && break
        sleep 1
    done

    drop_caches
    rm -f "$WORK_DIR"/lt_*.dat
    log "  -> $OUT"
}

# ─── Run All Experiments ──────────────────────────────────
log "╔══════════════════════════════════════════════════╗"
log "║   OOB Page Cache Dedup — Comprehensive Profiling ║"
log "╠══════════════════════════════════════════════════╣"
log "║  Work dir:    $WORK_DIR"
log "║  Results dir: $RESULTS_DIR"
log "╚══════════════════════════════════════════════════╝"
echo ""

run_exp1_memory_savings
run_exp2_scan_throughput
run_exp4_write_latency
run_exp5_fanout_scalability
run_exp6_live_trace

log ""
log "All experiments complete. Generating graphs..."
python3 "$SCRIPT_DIR/plot_results.py" "$RESULTS_DIR"
log "Done! Results in $RESULTS_DIR/"
