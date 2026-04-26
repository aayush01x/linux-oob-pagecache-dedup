#!/usr/bin/env python3
"""
plot_results.py — Generate publication-quality graphs from profiling CSVs.

Usage: python3 plot_results.py <results_dir>

Reads CSV files produced by run_comprehensive_profiling.sh and generates
PNG graphs + a comprehensive markdown report.
"""

import sys, os, csv
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

RESULTS_DIR = sys.argv[1] if len(sys.argv) > 1 else "results"

plt.rcParams.update({
    'figure.figsize': (10, 6),
    'font.size': 12,
    'axes.grid': True,
    'grid.alpha': 0.3,
    'lines.linewidth': 2,
    'lines.markersize': 8,
})

COLORS = ['#2196F3', '#4CAF50', '#FF5722', '#9C27B0', '#FF9800', '#00BCD4']

def read_csv(name):
    path = os.path.join(RESULTS_DIR, name)
    if not os.path.exists(path):
        print(f"  [skip] {name} not found")
        return []
    with open(path) as f:
        return list(csv.DictReader(f))

def savefig(name):
    path = os.path.join(RESULTS_DIR, name)
    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  -> {path}")

# ─── Plot 1: Memory Savings vs File Count ─────────────────
def plot_exp1():
    rows = read_csv("exp1_memory_savings.csv")
    if not rows: return
    n = [int(r['num_files']) for r in rows]
    total = [int(r['total_mb']) for r in rows]
    saved = [int(r['saved_kb']) / 1024 for r in rows]

    fig, ax1 = plt.subplots()
    ax1.bar([str(x) for x in n], total, color=COLORS[0], alpha=0.4, label='Total Data (MB)')
    ax1.bar([str(x) for x in n], saved, color=COLORS[1], alpha=0.8, label='Memory Saved (MB)')
    ax1.set_xlabel('Number of Identical Files')
    ax1.set_ylabel('Size (MB)')
    ax1.set_title('Memory Savings vs File Count (16MB per file)')
    ax1.legend()
    savefig('plot1_memory_savings.png')

# ─── Plot 2: Scanner Throughput vs File Size ──────────────
def plot_exp2():
    rows = read_csv("exp2_scan_throughput.csv")
    if not rows: return
    sz = [int(r['size_mb']) for r in rows]
    rate = [int(r['scan_rate_pages_per_sec']) for r in rows]
    deduped = [int(r['pages_deduped']) for r in rows]
    time_ms = [int(r['dedup_time_ns']) / 1e6 for r in rows]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    ax1.plot(sz, rate, marker='o', color=COLORS[0])
    ax1.set_xlabel('File Size (MB)')
    ax1.set_ylabel('Pages / Second')
    ax1.set_title('Scanner Throughput')
    ax1.yaxis.set_major_formatter(ticker.StrMethodFormatter('{x:,.0f}'))

    ax2.plot(sz, time_ms, marker='s', color=COLORS[2])
    ax2.set_xlabel('File Size (MB)')
    ax2.set_ylabel('Time (ms)')
    ax2.set_title('Dedup Completion Time')
    savefig('plot2_scan_throughput.png')

# ─── Plot 3: Read Latency Comparison ─────────────────────
def plot_exp3():
    rows = read_csv("exp3_read_latency.csv")
    if not rows: return
    sz = [int(r['size_mb']) for r in rows]
    nr = [int(r['normal_read_ns']) / 1e6 for r in rows]
    dr = [int(r['dedup_read_ns']) / 1e6 for r in rows]

    plt.figure()
    plt.plot(sz, nr, marker='o', color=COLORS[0], linestyle='--', label='Normal Read')
    plt.plot(sz, dr, marker='s', color=COLORS[1], label='Deduped Read')
    plt.xlabel('File Size (MB)')
    plt.ylabel('Read Time (ms)')
    plt.title('Read Latency: Normal vs Deduped (Page Cache Warm)')
    plt.legend()
    savefig('plot3_read_latency.png')

# ─── Plot 4: Write / COW Latency ─────────────────────────
def plot_exp4():
    rows = read_csv("exp4_write_latency.csv")
    if not rows: return
    sz = [int(r['size_mb']) for r in rows]
    nw = [int(r['normal_write_ns']) / 1e6 for r in rows]
    cw = [int(r['cow_full_write_ns']) / 1e6 for r in rows]
    sp = [int(r['cow_single_page_ns']) / 1e3 for r in rows]  # microseconds

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    ax1.plot(sz, nw, marker='o', color=COLORS[0], linestyle='--', label='Normal Write')
    ax1.plot(sz, cw, marker='s', color=COLORS[2], label='COW Full Overwrite')
    ax1.set_xlabel('File Size (MB)')
    ax1.set_ylabel('Time (ms)')
    ax1.set_title('Full-File Write Latency')
    ax1.legend()

    ax2.bar([str(s) for s in sz], sp, color=COLORS[3], alpha=0.7)
    ax2.set_xlabel('File Size (MB)')
    ax2.set_ylabel('Time (µs)')
    ax2.set_title('Single-Page COW Latency')
    savefig('plot4_write_latency.png')

# ─── Plot 5: Fanout Scalability ──────────────────────────
def plot_exp5():
    rows = read_csv("exp5_fanout_scalability.csv")
    if not rows: return
    n = [int(r['num_copies']) for r in rows]
    saved = [int(r['memory_saved_kb']) / 1024 for r in rows]
    time_ms = [int(r['dedup_time_ns']) / 1e6 for r in rows]

    fig, ax1 = plt.subplots()
    ax2 = ax1.twinx()

    ax1.bar([str(x) for x in n], saved, color=COLORS[1], alpha=0.6, label='Memory Saved (MB)')
    ax2.plot([str(x) for x in n], time_ms, marker='D', color=COLORS[2], label='Dedup Time (ms)')

    ax1.set_xlabel('Number of File Copies (8MB each)')
    ax1.set_ylabel('Memory Saved (MB)', color=COLORS[1])
    ax2.set_ylabel('Dedup Time (ms)', color=COLORS[2])
    ax1.set_title('Fanout Scalability: Savings & Time')
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left')
    savefig('plot5_fanout_scalability.png')

# ─── Plot 6: Live Scanner Trace ─────────────────────────
def plot_exp6():
    rows = read_csv("exp6_live_trace.csv")
    if not rows: return
    t = [int(r['time_s']) for r in rows]
    sc = [int(r['pages_scanned']) for r in rows]
    pd = [int(r['pages_deduped']) for r in rows]
    fq = [int(r['files_queued']) for r in rows]
    ck = [int(r['cached_kb']) / 1024 for r in rows]

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8), sharex=True)

    ax1.plot(t, sc, marker='.', color=COLORS[0], label='Pages Scanned')
    ax1.plot(t, pd, marker='.', color=COLORS[1], label='Pages Deduped')
    ax1.set_ylabel('Pages')
    ax1.set_title('Scanner Progress Over Time (4 x 32MB files)')
    ax1.legend()
    ax1.yaxis.set_major_formatter(ticker.StrMethodFormatter('{x:,.0f}'))

    ax2.plot(t, ck, marker='.', color=COLORS[3], label='Cached (MB)')
    ax2r = ax2.twinx()
    ax2r.plot(t, fq, marker='.', color=COLORS[4], label='Files Queued')
    ax2.set_xlabel('Time (seconds)')
    ax2.set_ylabel('Cached Memory (MB)', color=COLORS[3])
    ax2r.set_ylabel('Files Queued', color=COLORS[4])
    lines1, l1 = ax2.get_legend_handles_labels()
    lines2, l2 = ax2r.get_legend_handles_labels()
    ax2.legend(lines1 + lines2, l1 + l2)
    savefig('plot6_live_trace.png')

# ─── Plot 7: Accounting Stability ────────────────────────
def plot_exp7():
    rows = read_csv("exp7_accounting.csv")
    if not rows: return
    cyc = [int(r['cycle']) for r in rows]
    drift = [int(r['drift_kb']) for r in rows]

    plt.figure(figsize=(8, 4))
    plt.bar([str(c) for c in cyc], drift, color=COLORS[0], alpha=0.7)
    plt.axhline(y=0, color='red', linestyle='--', linewidth=1)
    plt.xlabel('Dedup-COW-Delete Cycle')
    plt.ylabel('Cached Drift (KB)')
    plt.title('NR_FILE_PAGES Accounting Stability (drift should be ~0)')
    savefig('plot7_accounting_stability.png')

# ─── Generate Markdown Report ────────────────────────────
def generate_report():
    rpt = os.path.join(RESULTS_DIR, "profiling_report.md")
    with open(rpt, 'w') as f:
        f.write("# OOB Page Cache Deduplication — Comprehensive Profiling Report\n\n")

        f.write("## Experiment 1: Memory Savings vs File Count\n")
        f.write("**Purpose**: Measure actual memory freed when deduplicating N identical 16MB files.\n\n")
        rows = read_csv("exp1_memory_savings.csv")
        if rows:
            f.write("| Files | Total (MB) | Saved (MB) | Pages Deduped | Time (s) |\n")
            f.write("|-------|-----------|-----------|---------------|----------|\n")
            for r in rows:
                f.write(f"| {r['num_files']} | {r['total_mb']} | {int(r['saved_kb'])//1024} | {r['pages_deduped']} | {r['time_s']} |\n")
        f.write("\n![Memory Savings](plot1_memory_savings.png)\n\n---\n\n")

        f.write("## Experiment 2: Scanner Throughput vs File Size\n")
        f.write("**Purpose**: Measure how scanner throughput scales with file size.\n\n")
        rows = read_csv("exp2_scan_throughput.csv")
        if rows:
            f.write("| Size (MB) | Time (ms) | Scanned | Deduped | Rate (pages/s) |\n")
            f.write("|-----------|----------|---------|---------|----------------|\n")
            for r in rows:
                f.write(f"| {r['size_mb']} | {int(r['dedup_time_ns'])//1000000} | {r['pages_scanned']} | {r['pages_deduped']} | {r['scan_rate_pages_per_sec']} |\n")
        f.write("\n![Throughput](plot2_scan_throughput.png)\n\n---\n\n")

        f.write("## Experiment 3: Read Latency — Normal vs Deduped\n")
        f.write("**Purpose**: Verify deduped reads have no overhead (same physical folio).\n\n")
        rows = read_csv("exp3_read_latency.csv")
        if rows:
            f.write("| Size (MB) | Normal Read (ms) | Dedup Read (ms) | Normal (MB/s) | Dedup (MB/s) |\n")
            f.write("|-----------|-----------------|----------------|---------------|-------------|\n")
            for r in rows:
                f.write(f"| {r['size_mb']} | {int(r['normal_read_ns'])//1000000} | {int(r['dedup_read_ns'])//1000000} | {r['normal_read_mbps']} | {r['dedup_read_mbps']} |\n")
        f.write("\n![Read Latency](plot3_read_latency.png)\n\n---\n\n")

        f.write("## Experiment 4: Write Latency — Normal vs COW\n")
        f.write("**Purpose**: Quantify the COW overhead when writing to deduped folios.\n\n")
        rows = read_csv("exp4_write_latency.csv")
        if rows:
            f.write("| Size (MB) | Normal Write (ms) | COW Write (ms) | Single-Page COW (µs) |\n")
            f.write("|-----------|------------------|---------------|---------------------|\n")
            for r in rows:
                f.write(f"| {r['size_mb']} | {int(r['normal_write_ns'])//1000000} | {int(r['cow_full_write_ns'])//1000000} | {int(r['cow_single_page_ns'])//1000} |\n")
        f.write("\n![Write Latency](plot4_write_latency.png)\n\n---\n\n")

        f.write("## Experiment 5: Fanout Scalability\n")
        f.write("**Purpose**: How dedup time and savings scale with number of copies.\n\n")
        rows = read_csv("exp5_fanout_scalability.csv")
        if rows:
            f.write("| Copies | Dedup Time (ms) | Pages Deduped | Saved (MB) |\n")
            f.write("|--------|----------------|---------------|------------|\n")
            for r in rows:
                f.write(f"| {r['num_copies']} | {int(r['dedup_time_ns'])//1000000} | {r['pages_deduped']} | {int(r['memory_saved_kb'])//1024} |\n")
        f.write("\n![Fanout](plot5_fanout_scalability.png)\n\n---\n\n")

        f.write("## Experiment 6: Scanner Live Trace\n")
        f.write("**Purpose**: Track scanner progress, memory reduction, and queue drain over time.\n\n")
        f.write("![Live Trace](plot6_live_trace.png)\n\n---\n\n")

        f.write("## Experiment 7: NR_FILE_PAGES Accounting Stability\n")
        f.write("**Purpose**: Verify that repeated dedup→COW→delete cycles don't leak NR_FILE_PAGES.\n\n")
        rows = read_csv("exp7_accounting.csv")
        if rows:
            f.write("| Cycle | Before (KB) | After Delete (KB) | Drift (KB) |\n")
            f.write("|-------|------------|-------------------|------------|\n")
            for r in rows:
                f.write(f"| {r['cycle']} | {r['cached_before_kb']} | {r['cached_after_delete_kb']} | {r['drift_kb']} |\n")
        f.write("\n![Accounting](plot7_accounting_stability.png)\n\n")

    print(f"  -> {rpt}")

# ─── Main ────────────────────────────────────────────────
if __name__ == '__main__':
    print("Generating graphs...")
    plot_exp1()
    plot_exp2()
    plot_exp3()
    plot_exp4()
    plot_exp5()
    plot_exp6()
    plot_exp7()
    print("Generating report...")
    generate_report()
    print("All done!")
