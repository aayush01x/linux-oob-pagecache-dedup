# OOB Page Cache Deduplication — Artifact Evaluation

**CS614 Project Artifact**

This artifact implements an out-of-band (OOB) background scanner inside the Linux kernel that identifies and merges identical page cache folios across (and within) files, reducing physical memory usage without modifying on-disk data. The deduplication subsystem integrates into the Linux memory management layer, operating transparently via a `posix_fadvise`-based opt-in interface.

---

## Table of Contents

1. [Artifact Directory Structure](#1-artifact-directory-structure)
2. [Setup Instructions](#2-setup-instructions)
3. [Features and Supported Functionalities](#3-features-and-supported-functionalities)
4. [Assumptions and Unsupported Features](#4-assumptions-and-unsupported-features)
5. [Getting Started](#5-getting-started)
6. [Detailed Evaluation](#6-detailed-evaluation)

---

## 1. Artifact Directory Structure

```
oob_pagecache_dedup_project/
├── README.md                          # This document
├── .config                            # Kernel configuration file for building the custom kernel
├── oob_dedup.patch                    # Kernel patch file containing all modifications
├── report.tex                         # Project report (LaTeX source)
│
└── tests/
    ├── run_all_tests.sh               # Central test runner — compiles, runs, and reports all tests
    ├── quick_test.sh                  # Quick "hello world" verification script
    ├── supply_input_test.sh           # Test with user-supplied input files
    │
    ├── clean_tests/                   # Correctness and stress test cases (C and shell)
    │   ├── common.h / common.c        # Shared helpers (create_and_queue utility)
    │   ├── run_clean_tests.sh         # Deprecated wrapper → forwards to run_all_tests.sh
    │   ├── test_01_cow_isolation.c
    │   ├── test_02_truncate_deduped.c
    │   ├── test_03_delete_then_read.c
    │   ├── test_04_sysfs_stats.c
    │   ├── test_05_fanout_cow.c
    │   ├── test_06_large_folio.c
    │   ├── test_07_intra_file_dedup.c
    │   ├── test_08_cascade_unlink.c
    │   ├── test_09_concurrent_trunc_cow.c
    │   ├── test_10_rededup_after_cow.c
    │   ├── test_11_mixed_operations.c
    │   ├── test_12_partial_truncate.c
    │   ├── test_13_page_accounting.c
    │   ├── test_14_rapid_lifecycle.c
    │   ├── test_15_cow_during_truncate.c
    │   ├── test_16_anchor_partial_match.c
    │   ├── test_18_memory_savings.sh
    │   ├── test_19_large_file_dedup.sh
    │   ├── test_20_anchor_trace.sh
    │   └── test_21_intra_file_large_dedup.sh
    │
    └── profile_tests/                 # Profiling and benchmarking suite
        ├── run_comprehensive_profiling.sh  # Full profiling suite (5 experiments)
        ├── plot_results.py            # Graph generation from profiling CSV data
        ├── profile_bench.c            # Comprehensive C benchmark helper
        └── profile_io.c              # Lightweight I/O profiling helper
```

---

## 2. Setup Instructions

### Hardware Requirements

| Resource | Requirement |
|----------|-------------|
| **CPU** | 4 cores (minimum) |
| **RAM** | 6 GB (minimum) |
| **Storage** | 30 GB disk formatted as **XFS** (no partitions required) |
| **Extra hardware** | None (no GPU required) |

### Software Requirements

| Software | Version / Details |
|----------|-------------------|
| **OS** | Ubuntu 24.04 LTS |
| **Kernel** | Linux 6.6.123 (custom, built from this artifact) |
| **Compiler** | `gcc` (for kernel build and test compilation) |
| **Build tools** | `make`, `flex`, `bison`, `libelf-dev`, `libssl-dev`, `bc` |
| **Python** | Python 3 |
| **matplotlib** | `pip3 install matplotlib` (for graph generation) |
| **sysstat (sar)** | `sudo apt install sysstat` (for system activity monitoring) |

### Kernel Compilation Instructions

**Human-time**: ~10 minutes of setup + waiting for compilation  
**Compute-time**: ~20–45 minutes (depends on CPU speed)

1. **Install build dependencies**:
   ```bash
   sudo apt update
   sudo apt install -y build-essential gcc make flex bison \
       libelf-dev libssl-dev bc dwarves
   ```

2. **Apply the patch** (if starting from a stock 6.6.123 kernel):
   ```bash
   cd /path/to/linux-6.6.123
   patch -p1 < /path/to/oob_pagecache_dedup_project/oob_dedup.patch
   ```

3. **Copy the kernel config**:
   ```bash
   cp /path/to/oob_pagecache_dedup_project/.config .config
   ```

4. **Build the kernel**:
   ```bash
   make -j$(nproc)
   sudo make modules_install
   sudo make install
   ```

5. **Reboot into the new kernel**:
   ```bash
   sudo reboot
   # Select the 6.6.123 kernel from GRUB if not default
   ```

6. **Verify the kernel is running**:
   ```bash
   uname -r
   # Expected output: 6.6.123
   ```

7. **Verify OOB dedup is active**:
   ```bash
   ls /sys/kernel/oob_dedup/
   # Expected: files_queued  folios_split  merge_threshold_pct
   #           pages_deduped  pages_scanned  pages_to_scan  sleep_millisecs
   ```

### Disk Setup (XFS)

The tests require an XFS-formatted filesystem for large folio support. If you don't have one:

```bash
# Option A: Use a loopback device (if no spare partition)
sudo dd if=/dev/zero of=/xfs_disk.img bs=1M count=10240   # 10 GB
sudo losetup /dev/loop0 /xfs_disk.img
sudo mkfs.xfs /dev/loop0
sudo mkdir -p /mnt/xfs
sudo mount /dev/loop0 /mnt/xfs

# Option B: If you have a spare partition /dev/sdX
sudo mkfs.xfs /dev/sdX
sudo mkdir -p /mnt/xfs
sudo mount /dev/sdX /mnt/xfs
```

The test runner auto-detects XFS mount points. To override, set:
```bash
export TEST_WORKDIR=/mnt/xfs
```

### Install Python Dependencies

```bash
pip3 install matplotlib
sudo apt install -y sysstat
```

---

## 3. Features and Supported Functionalities

The implementation supports the following features. Each feature is validated by one or more automated tests.

| # | Feature | Description | Validating Tests |
|---|---------|-------------|-----------------|
| 1 | **Inter-File Deduplication** | Identifies identical page cache content across different files and merges them into a single physical folio via XArray pointer redirection. | `test_01`, `test_02`, `test_03`, `test_05`, `test_08`, `test_18`, `test_19` |
| 2 | **Intra-File Deduplication** | Detects and merges duplicate pages within the same file (same `address_space`, different indices). | `test_07`, `test_21` |
| 3 | **Copy-on-Write (COW)** | When a write targets a deduplicated folio, a private copy is transparently allocated and swapped in via the iomap write path. The sibling file's data remains untouched. | `test_01`, `test_05`, `test_10`, `test_15` |
| 4 | **Safe Truncation of Deduped Files** | Truncating or deleting one file in a dedup group correctly dissolves the sharing; sibling files survive with intact data. Handles batch removal, intra-file dissolution, and partial truncation. | `test_02`, `test_03`, `test_08`, `test_12`, `test_15` |
| 5 | **NR_FILE_PAGES Accounting Integrity** | Physical memory accounting (`/proc/meminfo` Cached) remains correct through dedup, COW, truncation, and deletion cycles. No underflow or drift. | `test_13`, `test_18` |
| 6 | **Sysfs Runtime Interface** | Exposes tunable parameters (`sleep_millisecs`, `pages_to_scan`, `merge_threshold_pct`) and read-only counters (`pages_scanned`, `pages_deduped`, `files_queued`, `folios_split`) under `/sys/kernel/oob_dedup/`. | `test_04` |
| 7 | **Fanout Deduplication (N-way)** | Multiple files (3+) sharing identical content are correctly merged; COW on any file isolates the write without affecting others. | `test_05`, `test_08` |
| 8 | **Large Folio Support** | Correctly handles multi-order (e.g., order-4, 64 KB) XFS folios during dedup, COW, and truncation. Includes order-aware XArray operations. | `test_06`, `test_19`, `test_21` |
| 9 | **Anchor-Based Sampling Hash** | Efficient duplicate detection using strategically placed CRC32 anchor hashes within large folios. Supports partial-match detection and folio splitting. | `test_16`, `test_20` |
| 10 | **Re-Dedup After COW** | After COW breaks sharing, re-queuing files via `posix_fadvise` triggers re-scanning and re-merging of content that is again identical. | `test_10` |
| 11 | **Concurrent Operation Safety** | Safe under concurrent truncation, COW writes, and deletion via trylock-based deadlock avoidance and address-ordered locking. | `test_09`, `test_11`, `test_14`, `test_15` |
| 12 | **Memory Savings** | Measurable reduction in physical memory usage (Cached in `/proc/meminfo`) proportional to duplicate content. For N identical files of M pages each, saves (N-1)×M×4 KB. | `test_18`, `test_19` |
| 13 | **posix_fadvise Entry Point** | User-space opt-in via `posix_fadvise(fd, 0, 0, POSIX_FADV_DEDUP)` (advice value 8). Non-intrusive, returns immediately. | All tests (used as the dedup trigger) |

### Known Issues

| Issue | Description | Frequency |
|-------|-------------|-----------|
| Read-path spin under extreme concurrency | Under heavy concurrent zero-copy I/O (`splice`/`sendfile`) on deduplicated folios, the read-batch iterator can spin due to an ordering race between dissolution and XArray iteration. A 100,000-iteration diagnostic cap prevents lockup. | Rare — only under extreme concurrent zero-copy workloads |

---

## 4. Assumptions and Unsupported Features

### Assumptions

- **Filesystem**: The implementation is tested and validated on **XFS**. While the core dedup logic operates at the VFS/MM layer and is filesystem-agnostic, the COW hook is placed in the **iomap buffered I/O** write path (`fs/iomap/buffered-io.c`), which is used by XFS. Other iomap-based filesystems (e.g., ext4 with iomap) may work but are not tested.
- **Disk format**: The working directory should be on an XFS partition to enable large folio support (order-4 folios). Tests will still run on ext4 but will fall back to order-0 (4 KB) folios.
- **Root privileges**: All tests must be run as **root** (`sudo`) because they access `/sys/kernel/oob_dedup/`, `/proc/sys/vm/drop_caches`, and create files on the XFS partition.
- **Single-node**: The system is designed for single-machine operation. No distributed or networked dedup.
- **Files must be in page cache**: Dedup operates on in-memory page cache folios. Files must be read into memory before scanning can merge them.
- **No Kconfig gate**: The OOB dedup module is compiled directly into the kernel (`obj-y`) — there is no `CONFIG_OOB_DEDUP` option to toggle.

### Unsupported Features

| Feature | Reason |
|---------|--------|
| **Memory-mapped (mmap) file dedup** | Folios that are `folio_mapped()` (have user-space page-table entries) are excluded from dedup. Supporting mmap'd files would require page-table-level COW analogous to KSM, which is outside the scope of this work. |
| **Non-iomap filesystems** | Filesystems that do not use the iomap buffered I/O layer (e.g., legacy ext4, tmpfs, NFS) will not trigger the COW hook. Dedup may still identify duplicates, but writes to deduped folios will corrupt shared data. |
| **Persistent dedup metadata** | Dedup state is entirely in-memory. Rebooting clears all dedup sharing. |
| **Cgroup-scoped dedup** | Currently dedup is system-wide. No per-cgroup or per-namespace scoping. |
| **NUMA-aware placement** | No logic to ensure deduped folios are placed on optimal NUMA nodes. |

---

## 5. Getting Started

This section provides a quick verification path to confirm basic artifact functionality within **~15 minutes**.

### Step 1: Verify Kernel and Sysfs (Human-time: 2 min)

```bash
# Confirm custom kernel
uname -r
# Expected: 6.6.123

# Confirm OOB dedup sysfs exists
cat /sys/kernel/oob_dedup/pages_scanned
cat /sys/kernel/oob_dedup/pages_deduped
cat /sys/kernel/oob_dedup/files_queued
# All should return 0 (or a small number if files were already queued)
```

### Step 2: Run the Quick Verification Test (Human-time: 1 min, Compute-time: ~30 sec)

A fully automated "hello world" script is provided that creates two identical files, triggers dedup, verifies memory savings, and tests COW isolation:

```bash
cd /path/to/oob_pagecache_dedup_project/tests

# Run the quick verification (must be root)
sudo bash quick_test.sh
```

The script auto-detects an XFS mount point. To specify a directory manually:
```bash
sudo bash quick_test.sh /mnt/xfs
```

**What it does**:
1. Verifies kernel and sysfs interface
2. Creates two identical 4 MB files
3. Loads them into page cache and records baseline Cached memory
4. Triggers dedup via `posix_fadvise(POSIX_FADV_DEDUP)`
5. Waits for the scanner to finish
6. Verifies pages were deduplicated and memory was saved
7. Checks data integrity via md5sum
8. Tests COW isolation by writing to one file and verifying the other is untouched

**Expected output**: `[PASS] Quick verification test PASSED`

### Step 3: Run the Automated Test Suite (Human-time: 2 min setup, Compute-time: ~4 min)

```bash
cd /path/to/oob_pagecache_dedup_project/tests

# Run all tests (must be root)
sudo bash run_all_tests.sh
```

The runner compiles and executes all 20 tests across 5 categories:
- **basic** (6 tests): COW, truncation, deletion, sysfs, fanout, large folios
- **stress** (6 tests): intra-file, cascade, concurrent ops, mixed operations
- **regression** (3 tests): NR_FILE_PAGES accounting, rapid lifecycle, COW during truncate
- **anchor** (1 test): anchor-based partial match detection
- **benchmark** (4 tests): memory savings, large file dedup, anchor tracing

A `test_report.md` is automatically generated in the `tests/` directory with PASS/FAIL results and timing.

To run a specific category only:
```bash
sudo bash run_all_tests.sh --category basic
```

### Step 4: Supply Your Own Input Files (Human-time: 2 min, Compute-time: depends on file size)

An automated script is provided to test dedup with your own files:

```bash
cd /path/to/oob_pagecache_dedup_project/tests

# Supply at least 2 files with identical (or partially identical) content
sudo bash supply_input_test.sh /path/to/your/file1.dat /path/to/your/file2.dat
```

**What it does**:
1. Copies your files to an XFS working directory
2. Records pre-dedup checksums
3. Loads files into page cache and records baseline memory
4. Triggers dedup and monitors progress with a live table (pages deduped, cached memory, files queued)
5. Reports memory savings
6. Verifies data integrity by comparing post-dedup checksums against originals

You can supply any number of files (minimum 2). The files should have identical content for dedup to succeed. Example with 3 files:
```bash
sudo bash supply_input_test.sh data_a.bin data_b.bin data_c.bin
```

---

## 6. Detailed Evaluation

### 6.1 Profiling Experiments

The profiling suite measures performance characteristics of the deduplication system across varying file sizes and workload configurations.

**How to run**:
```bash
cd /path/to/oob_pagecache_dedup_project/tests/profile_tests
sudo bash run_comprehensive_profiling.sh [optional: /path/to/xfs/dir]
```

**Human-time**: ~2 min setup  
**Compute-time**: ~15–30 minutes

The suite runs 5 experiments:

| Exp # | Name | Purpose | Output File |
|-------|------|---------|-------------|
| 1 | Memory Savings vs. File Count | Measure actual memory freed when deduplicating N identical 16 MB files (N = 2, 4, 8, 16) | `results/exp1_memory_savings.csv` |
| 2 | Scanner Throughput vs. File Size | Measure scanner pages/second across file sizes 4–64 MB | `results/exp2_scan_throughput.csv` |
| 3 | Write Latency — Normal vs. COW | Quantify COW overhead: full-file overwrite and single-page COW latency | `results/exp4_write_latency.csv` |
| 4 | Fanout Scalability | How dedup time and savings scale with number of file copies (2–32 copies of 8 MB) | `results/exp5_fanout_scalability.csv` |
| 5 | Scanner Live Trace | Second-by-second trace of `pages_scanned`, `pages_deduped`, `files_queued`, and `Cached` memory during a 4×32 MB dedup run | `results/exp6_live_trace.csv` |

**Expected results**:
- Memory savings scale linearly: N identical files → ~(N-1) × file_size freed
- Scanner throughput: ~3,000–5,000 pages/second at default settings
- COW write overhead: 30–80% slower than normal writes
- Fanout: dedup time grows sub-linearly; savings scale linearly with N

**Generated plots** (in `results/` directory):
- `plot1_memory_savings.png`
- `plot2_scan_throughput.png`
- `plot4_write_latency.png`
- `plot5_fanout_scalability.png`
- `plot6_live_trace.png`
- `profiling_report.md` — Full markdown report with tables and embedded figures

**How to regenerate plots from existing CSV data**:
```bash
cd /path/to/oob_pagecache_dedup_project/tests/profile_tests
python3 plot_results.py results/
```

---

### 6.2 Correctness Test Cases

All tests are automated and can be run via a single command. Each test returns exit code 0 on success and 1 on failure. The test runner (`run_all_tests.sh`) generates a `test_report.md` with PASS/FAIL status and elapsed time for each test.

**How to run all tests**:
```bash
cd /path/to/oob_pagecache_dedup_project/tests
sudo bash run_all_tests.sh
```

**Estimated total runtime**: ~4 minutes (measured: 244 seconds)

---

#### Category: Basic (Core Functionality)

| # | Test Name | Purpose | Runtime | Expected Result |
|---|-----------|---------|---------|----------------|
| 1 | COW Isolation | Creates two identical files, waits for dedup, writes to file 1, verifies file 2 is untouched. Confirms COW breaks sharing correctly. | 5s | PASS — written file has new data; sibling unchanged |
| 2 | Truncate Deduped File | Truncates one file in a dedup pair. Verifies the sibling file survives with intact data. | 5s | PASS — truncated file removed; sibling reads correctly |
| 3 | Delete Then Read | Deletes one file from a dedup pair, then reads the survivor. Validates dissolution under deletion. | 5s | PASS — survivor returns original content |
| 4 | Sysfs Stats | Triggers dedup and verifies that `/sys/kernel/oob_dedup/` counters (`pages_scanned`, `pages_deduped`, `files_queued`) increment correctly. | 5s | PASS — counters reflect expected values |
| 5 | Fanout COW (3-way) | Three files share identical content. COW write on each file independently; all files retain correct private data. | 5s | PASS — each file has its own modified data |
| 6 | Large Folio Dedup+COW | Tests dedup and COW on XFS order-4 (64 KB) folios. Validates order-aware XArray operations. | 5s | PASS — large folio dedup and COW succeed |

#### Category: Stress (Concurrency and Edge Cases)

| # | Test Name | Purpose | Runtime | Expected Result |
|---|-----------|---------|---------|----------------|
| 7 | Intra-File Dedup | Creates a file with duplicate pages within itself. Verifies intra-file dedup, COW, and truncation. | 8s | PASS — internal duplicates merged; COW and truncation work |
| 8 | Cascade Unlink (5-way) | Five files sharing content. Sequentially delete each; verify no orphaned folios or crashes. | 10s | PASS — all files deleted cleanly, no kernel warnings |
| 9 | Concurrent Trunc+COW | Multi-threaded stress: concurrent truncation and COW writes on shared files. Tests lock safety. | 9s | PASS — no deadlocks or crashes |
| 10 | Re-Dedup After COW | After COW breaks sharing, re-queues files and verifies they are re-merged. | 17s | PASS — pages re-deduplicated after COW |
| 11 | Combined Operations | Inter-file + intra-file dedup, hole-punch, partial truncate, COW, and delete in a single test. | 11s | PASS — all operations complete without crash |
| 12 | Partial Truncate | Mid-page truncation boundaries on deduped files (5 scenarios: inter-file, 1-byte, intra-file, successive, extend-after-truncate). | 42s | PASS — all partial truncation scenarios handled correctly |

#### Category: Regression (Bug-Triggering Tests)

| # | Test Name | Purpose | Runtime | Expected Result |
|---|-----------|---------|---------|----------------|
| 13 | Page Accounting | Runs dedup + delete cycles and checks `/proc/meminfo` Cached for NR_FILE_PAGES underflow. Regression test for the accounting corruption bug. | 21s | PASS — Cached does not go negative |
| 14 | Rapid Lifecycle | Create → dedup → delete files in 20 rapid iterations. Stress-tests scanner queue management and inode eviction. | 6s | PASS — no crash, no orphaned slots |
| 15 | COW During Truncate | Concurrent COW write during truncation of a shared file. Tests the interaction between the iomap COW path and truncation dissolution. | 11s | PASS — no deadlock or data corruption |

#### Category: Anchor (Anchor Hashing Tests)

| # | Test Name | Purpose | Runtime | Expected Result |
|---|-----------|---------|---------|----------------|
| 16 | Anchor Partial Match | Creates files with partially matching content (255/256 pages identical). Verifies that the anchor hash detects partial matches and triggers folio splitting for finer-grained dedup. | 8s | PASS — partial matches detected; folios split; data integrity verified |

#### Category: Benchmark (Memory Savings and Scale)

| # | Test Name | Purpose | Runtime | Expected Result |
|---|-----------|---------|---------|----------------|
| 18 | Memory Savings | Creates 10 identical 20 MB files (200 MB total), deduplicates, and measures Cached reduction. Verifies all files remain readable. | 35s | PASS — ~194 MB freed by dedup (from ~200 MB loaded) |
| 19 | Large File Dedup | 3 × 32 MB files (96 MB total). Deduplicates with live progress monitoring (pages deduped, cached memory, files queued). Measures scan throughput. | 9s | PASS — ~88 MB freed; data integrity preserved; ~19 MB/s scan throughput |
| 20 | Anchor Trace | Runs anchor partial match test and captures full dmesg trace of anchor hashing: geometry computation, hash values, table lookups, partial match splits, and exact merges. | 8s | PASS — anchor trace logged; 10 exact merges, 1 partial match split |
| 21 | Intra-File Large Dedup | Creates a 512 MB file with identical data, deduplicates within the file. Monitors memory via `sar`. Measures ~504 MB freed from ~512 MB loaded. | 15s | PASS — intra-file large dedup works; ~504 MB freed |

---

### 6.3 How to Access Results

| Artifact | Location |
|----------|----------|
| Test report (auto-generated) | `tests/test_report.md` |
| Profiling CSVs | `tests/profile_tests/results/*.csv` |
| Profiling plots | `tests/profile_tests/results/*.png` |
| Profiling report | `tests/profile_tests/results/profiling_report.md` |
| Kernel logs (for debugging) | `sudo dmesg \| grep oob_dedup` |
| Anchor trace log | `tests/clean_tests/dmesg_anchor_trace.log` |
| Live sysfs counters | `cat /sys/kernel/oob_dedup/*` |
