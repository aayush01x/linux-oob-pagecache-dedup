#!/usr/bin/env python3
"""
plot_eviction.py  —  OOB Eviction Timing: Stacked-Bar + Line Plot
==================================================================
Reads eviction_profile_results.json and generates eviction_breakdown.png.

Usage:
  python3 plot_eviction.py eviction_profile_results.json [--output-dir .]

The chart shows:
  - Stacked bars: Hash / Compare / Merge time per size
  - Line overlay: Total Active time
  - Y-axis: milliseconds
  - X-axis: file size (MB)
"""

import sys, os, json, argparse

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("json_file", help="Path to eviction_profile_results.json")
    p.add_argument("--output-dir", default=".")
    return p.parse_args()

def ns_to_ms(ns): return ns / 1_000_000

def main():
    args = parse_args()

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import matplotlib.ticker as mticker
        import numpy as np
    except ImportError:
        sys.exit("[ERROR] matplotlib not installed. Run: pip3 install matplotlib numpy")

    with open(args.json_file) as f:
        data = json.load(f)

    sizes   = data["sizes"]
    results = data["results"]

    active_ms  = [ns_to_ms(results[str(sz)]["active_ns"])  for sz in sizes]
    hash_ms    = [ns_to_ms(results[str(sz)]["hash_ns"])    for sz in sizes]
    compare_ms = [ns_to_ms(results[str(sz)]["compare_ns"]) for sz in sizes]
    merge_ms   = [ns_to_ms(results[str(sz)]["merge_ns"])   for sz in sizes]

    # Remaining "overhead" = active - (hash + compare + merge)
    overhead_ms = [max(0, a - h - c - m)
                   for a, h, c, m in zip(active_ms, hash_ms, compare_ms, merge_ms)]

    x     = np.arange(len(sizes))
    width = 0.55

    # ── Style ─────────────────────────────────────────────────────────────────
    PALETTE = {
        "hash":     "#4C72B0",
        "compare":  "#55A868",
        "merge":    "#C44E52",
        "overhead": "#8172B2",
        "active":   "#DD8452",
    }

    fig, ax = plt.subplots(figsize=(11, 6))
    fig.patch.set_facecolor("#F9F9F9")
    ax.set_facecolor("#F9F9F9")

    # Stacked bars
    bars_hash = ax.bar(x, hash_ms,    width, label="Hash",     color=PALETTE["hash"],     zorder=3)
    bars_cmp  = ax.bar(x, compare_ms, width, label="Compare",  color=PALETTE["compare"],  bottom=hash_ms, zorder=3)
    bottom_mc = [h+c for h,c in zip(hash_ms, compare_ms)]
    bars_mrg  = ax.bar(x, merge_ms,   width, label="Merge",    color=PALETTE["merge"],    bottom=bottom_mc, zorder=3)
    bottom_all= [h+c+m for h,c,m in zip(hash_ms, compare_ms, merge_ms)]
    ax.bar(x, overhead_ms, width, label="Overhead",  color=PALETTE["overhead"],
           bottom=bottom_all, alpha=0.55, zorder=3)

    # Active line
    ax.plot(x, active_ms, marker="o", linewidth=2.2, markersize=6,
            color=PALETTE["active"], label="Total Active", zorder=5)

    # Labels & grid
    ax.set_xlabel("File Size (MB)", fontsize=12, labelpad=8)
    ax.set_ylabel("Time (ms)",      fontsize=12, labelpad=8)
    ax.set_title("OOB Dedup: Per-Phase Eviction Timing Breakdown",
                 fontsize=14, fontweight="bold", pad=12)
    ax.set_xticks(x)
    ax.set_xticklabels([str(s) for s in sizes], rotation=30, ha="right")
    ax.yaxis.set_major_formatter(mticker.FormatStrFormatter("%.1f"))
    ax.grid(axis="y", linestyle="--", alpha=0.6, zorder=0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    ax.legend(loc="upper left", framealpha=0.85, fontsize=10)

    plt.tight_layout()

    out_path = os.path.join(args.output_dir, "eviction_breakdown.png")
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[plot] Saved → {out_path}")

    # ── Second figure: individual phase lines (easier to read per-phase slopes)
    fig2, ax2 = plt.subplots(figsize=(10, 5))
    fig2.patch.set_facecolor("#F9F9F9")
    ax2.set_facecolor("#F9F9F9")

    for label, values, color, ls in [
        ("Total Active", active_ms,  PALETTE["active"],  "-"),
        ("Hash",         hash_ms,    PALETTE["hash"],    "--"),
        ("Compare",      compare_ms, PALETTE["compare"], "-."),
        ("Merge",        merge_ms,   PALETTE["merge"],   ":"),
    ]:
        ax2.plot(sizes, values, marker="o", linewidth=2,
                 label=label, color=color, linestyle=ls, markersize=5)

    ax2.set_xlabel("File Size (MB)", fontsize=12)
    ax2.set_ylabel("Time (ms)",      fontsize=12)
    ax2.set_title("OOB Dedup: Phase Scaling vs File Size",
                  fontsize=13, fontweight="bold")
    ax2.grid(linestyle="--", alpha=0.55)
    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_visible(False)
    ax2.legend(fontsize=10)
    plt.tight_layout()

    line_path = os.path.join(args.output_dir, "eviction_phase_lines.png")
    plt.savefig(line_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[plot] Saved → {line_path}")

if __name__ == "__main__":
    main()
