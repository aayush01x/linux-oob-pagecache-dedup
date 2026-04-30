#!/usr/bin/env python3
"""
run_eviction_profile.py  —  OOB Page-Cache Dedup: Eviction Timing Profiler
============================================================================
Sweeps file sizes [1,2,4,8,16,32,64,128,256,512,1024,1536] MB, measures
per-phase eviction timing (hash / compare / merge / active) via sysfs, and
produces:
  eviction_profile_results.json   — raw nanosecond data
  eviction_breakdown_table.tex    — LaTeX table (matches Table 1)
  eviction_breakdown.png          — stacked-bar + line plot

Usage (on Linux VM, as root):
  python3 run_eviction_profile.py [--dir /mnt/xfs/test] [--runs N] [--no-plot]
"""

import os, sys, json, time, shutil, subprocess, argparse

SYSFS_ROOT = "/sys/kernel/oob_dedup"
SIZES_DEFAULT = "1,2,4,8,16,32,64,128,256,512,1024,1536"

# ── CLI ───────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--dir",        default=None)
    p.add_argument("--sizes",      default=SIZES_DEFAULT)
    p.add_argument("--runs",       type=int, default=1)
    p.add_argument("--no-plot",    action="store_true")
    p.add_argument("--bench",      default=None)
    p.add_argument("--output-dir", default=".")
    return p.parse_args()

# ── Helpers ───────────────────────────────────────────────────────────────────
def check_sysfs():
    if not os.path.isdir(SYSFS_ROOT):
        sys.exit(f"[ERROR] {SYSFS_ROOT} not found — module loaded?")
    for attr in ["reset_stats","time_hash_ns","time_compare_ns",
                 "time_merge_ns","time_active_ns","files_queued"]:
        if not os.path.exists(os.path.join(SYSFS_ROOT, attr)):
            sys.exit(f"[ERROR] Missing sysfs attr: {attr} — rebuild kernel.")
    print("[OK] sysfs interface verified.")

def detect_test_dir():
    try:
        out = subprocess.run(["findmnt","-t","xfs","-n","-o","TARGET"],
                             capture_output=True, text=True, timeout=5)
        for line in out.stdout.strip().splitlines():
            p = line.strip()
            if p and os.path.isdir(p) and os.access(p, os.W_OK):
                return os.path.join(p, "oob_eviction_profile")
    except Exception:
        pass
    return "/tmp/oob_eviction_profile"

def ensure_bench(bench_arg, script_dir, test_dir):
    if bench_arg and os.path.isfile(bench_arg) and os.access(bench_arg, os.X_OK):
        return bench_arg
    src = os.path.join(script_dir, "profile_bench.c")
    if not os.path.isfile(src):
        sys.exit(f"[ERROR] profile_bench.c not found at {src}")
    dst = os.path.join(test_dir, "profile_bench")
    print(f"[bench] compiling → {dst}")
    r = subprocess.run(["gcc","-O2","-pthread","-o",dst,src],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"[ERROR] Compile failed:\n{r.stderr}")
    print("[bench] OK.")
    return dst

def drop_caches():
    subprocess.run(["sync"], check=True)
    with open("/proc/sys/vm/drop_caches","w") as f:
        f.write("3\n")
    time.sleep(0.5)

def run_cmd(cmd, check=True):
    r = subprocess.run(cmd, shell=isinstance(cmd,str),
                       capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}\n{r.stderr}")
    return r.stdout

def warm_file(path):
    with open(path,"rb") as f:
        while f.read(1<<20): pass

def parse_kv(stdout):
    d = {}
    for line in stdout.splitlines():
        if ": " in line:
            k, _, v = line.partition(": ")
            try: d[k.strip()] = int(v.strip())
            except ValueError:
                try: d[k.strip()] = float(v.strip())
                except ValueError: d[k.strip()] = v.strip()
    return d

def ns_to_ms(ns): return ns / 1_000_000

# ── Per-size profiling ────────────────────────────────────────────────────────
def profile_size(bench, size_mb, test_dir, runs):
    pa = os.path.join(test_dir, f"evA_{size_mb}.dat")
    pb = os.path.join(test_dir, f"evB_{size_mb}.dat")

    print(f"  [setup] {size_mb} MB file pair")
    run_cmd(f"dd if=/dev/zero bs=1M count={size_mb} 2>/dev/null "
            f"| tr '\\0' 'A' > {pa}")
    run_cmd(f"cp {pa} {pb}")

    acc = dict(active_ns=0, hash_ns=0, compare_ns=0, merge_ns=0,
               pages_deduped=0, pages_scanned=0)

    for i in range(runs):
        print(f"  [run {i+1}/{runs}] warm...", end="", flush=True)
        drop_caches()
        warm_file(pa); warm_file(pb)
        print(" profile...", end="", flush=True)
        out = run_cmd([bench, "--eviction-profile", pa, pb])
        p = parse_kv(out)
        print(f" deduped={p.get('eviction_pages_deduped','?')}")
        acc["active_ns"]     += p.get("eviction_active_ns",  0)
        acc["hash_ns"]       += p.get("eviction_hash_ns",    0)
        acc["compare_ns"]    += p.get("eviction_compare_ns", 0)
        acc["merge_ns"]      += p.get("eviction_merge_ns",   0)
        acc["pages_deduped"] += p.get("eviction_pages_deduped", 0)
        acc["pages_scanned"] += p.get("eviction_pages_scanned", 0)

    for path in [pa, pb]:
        try: os.remove(path)
        except OSError: pass

    return {k: v/runs for k,v in acc.items()}

# ── Output ────────────────────────────────────────────────────────────────────
def print_table(results, sizes):
    hdr = f"{'Size':>10} {'Active (ms)':>14} {'Hash (ms)':>12} " \
          f"{'Compare (ms)':>14} {'Merge (ms)':>12}"
    sep = "-"*len(hdr)
    print(f"\n{sep}\n  Table 1: Profiling Data Breakdown\n{sep}\n{hdr}\n{sep}")
    for sz in sizes:
        d = results[sz]
        print(f"{sz:>10} {ns_to_ms(d['active_ns']):>14.3f} "
              f"{ns_to_ms(d['hash_ns']):>12.3f} "
              f"{ns_to_ms(d['compare_ns']):>14.3f} "
              f"{ns_to_ms(d['merge_ns']):>12.3f}")
    print(sep+"\n")

def write_latex(results, sizes, path):
    lines = [
        r"\begin{table}[h]", r"  \centering",
        r"  \caption{Profiling Data Breakdown (Time in ms)}",
        r"  \label{tab:eviction-profile}",
        r"  \begin{tabular}{|r|r|r|r|r|}",
        r"    \hline",
        r"    \textbf{Size (MB)} & \textbf{Total Active (ms)} & "
        r"\textbf{Hash (ms)} & \textbf{Compare (ms)} & \textbf{Merge (ms)} \\",
        r"    \hline",
    ]
    for sz in sizes:
        d = results[sz]
        lines.append(
            f"    {sz} & {ns_to_ms(d['active_ns']):.3f} & "
            f"{ns_to_ms(d['hash_ns']):.3f} & "
            f"{ns_to_ms(d['compare_ns']):.3f} & "
            f"{ns_to_ms(d['merge_ns']):.3f} \\\\"
        )
        lines.append(r"    \hline")
    lines += [r"  \end{tabular}", r"\end{table}"]
    with open(path,"w") as f:
        f.write("\n".join(lines)+"\n")
    print(f"[output] LaTeX → {path}")

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    args = parse_args()
    if os.geteuid() != 0:
        print("[WARN] not root — drop_caches/sysfs writes may fail")
    check_sysfs()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    test_dir   = args.dir or detect_test_dir()
    out_dir    = args.output_dir
    os.makedirs(test_dir, exist_ok=True)
    os.makedirs(out_dir,  exist_ok=True)

    requested = [int(s) for s in args.sizes.split(",")]
    avail_mb  = shutil.disk_usage(test_dir).free // (1024*1024)
    sizes = [s for s in requested if s*3 < avail_mb - 200] or [requested[0]]
    if len(sizes) < len(requested):
        skipped = sorted(set(requested)-set(sizes))
        print(f"[WARN] Skipping {skipped} MB (disk space).")

    print(f"[info] dir={test_dir}  sizes={sizes}  runs={args.runs}")

    bench = ensure_bench(args.bench, script_dir, test_dir)
    results = {}

    for sz in sizes:
        print(f"\n{'='*56}\n  Profiling {sz} MB\n{'='*56}")
        results[sz] = profile_size(bench, sz, test_dir, args.runs)

    # Save JSON
    json_path = os.path.join(out_dir, "eviction_profile_results.json")
    with open(json_path,"w") as f:
        json.dump({"sizes":sizes, "results":{str(k):v for k,v in results.items()}}, f, indent=2)
    print(f"[output] JSON → {json_path}")

    print_table(results, sizes)

    tex_path = os.path.join(out_dir, "eviction_breakdown_table.tex")
    write_latex(results, sizes, tex_path)

    if not args.no_plot:
        try:
            plot_script = os.path.join(script_dir, "plot_eviction.py")
            subprocess.run([sys.executable, plot_script, json_path,
                            "--output-dir", out_dir], check=True)
        except Exception as e:
            print(f"[WARN] Plot failed: {e} — run plot_eviction.py manually.")

    print("\n[DONE]")
    print(f"  JSON  : {json_path}")
    print(f"  LaTeX : {tex_path}")
    if not args.no_plot:
        print(f"  Plot  : {os.path.join(out_dir,'eviction_breakdown.png')}")

if __name__ == "__main__":
    main()
