# OOB Page Cache Deduplication — Complete Project Context

## 1. Project Overview

Kernel-level, out-of-band page cache deduplication for Linux 6.6. Files with identical content share physical folios in the page cache, reducing memory usage. Operates transparently — userspace triggers dedup via `posix_fadvise(fd, 0, 0, POSIX_FADV_DEDUP=8)`, and a background kernel thread (`oob_dedupd`) handles scanning and merging.

**Base kernel:** Linux 6.6.123+
**Primary filesystem:** XFS (supports large folios natively)
**Works on:** ext4, tmpfs, any filesystem using the generic page cache

---

## 2. Architecture

```
User calls posix_fadvise(fd, POSIX_FADV_DEDUP)
        │
        ▼
oob_dedup_add_file(mapping)     ← Queues file's address_space
        │
        ▼
file_dedup_list (linked list)   ← Round-robin queue of files to scan
        │
        ▼
oob_dedupd kthread (sleeps 20ms between rounds)
        │
        ▼
oob_dedup_do_scan()
  ├─ For each queued file, iterate page cache (filemap_get_folio)
  ├─ hash_folio() → CRC32 of entire folio content
  ├─ check_and_store_folio() → lookup hash in oob_folio_hash table
  │    ├─ No match → store hash entry
  │    ├─ Exact match (all pages identical) → deduplicate_folio()
  │    └─ Partial match ≥ threshold → split_folio() + re-scan
  └─ Remove slot when file fully scanned
```

### Key Design Decisions

1. **Full-folio hashing:** Hashes the ENTIRE folio (all pages) as one CRC32. Identical files at same alignment → match. Shuffled/offset content → no match for large folios. Per-page hashing or split-then-hash planned as future improvement.

2. **`folio->mapping` tagging:** Deduped folios store `oob_dedup_info*` in `folio->mapping` with bit 2 set (`PAGE_MAPPING_DEDUP = 0x4`). This replaces the normal `address_space*` pointer, so ALL kernel code that dereferences `folio->mapping` must check `folio_test_dedup()` first.

3. **Symmetric rmap list:** Each deduped folio has an `oob_dedup_info` containing an rmap list of all `{mapping, index}` pairs pointing to it. This allows O(n) lookup of which files/indices share the folio.

4. **COW on write:** When userspace writes to a deduped page, `oob_folio_break_dedup()` allocates a fresh folio, copies data, swaps the XArray entry, and removes the rmap entry. The original folio survives for other sharers.

---

## 3. Data Structures

### `oob_dedup_info` (tagged in `folio->mapping`)
```c
struct oob_dedup_info {
    spinlock_t lock;
    struct list_head rmap_list;    // list of oob_dedup_rmap_entry
    unsigned int rmap_count;       // number of XArray entries sharing this folio
};
```
Allocated from `dedup_info_cache` (8-byte aligned for tagging). Freed when `rmap_count` drops to 1 (dissolution).

### `oob_dedup_rmap_entry`
```c
struct oob_dedup_rmap_entry {
    struct address_space *mapping;  // which file
    pgoff_t index;                  // which offset in that file
    struct list_head list;
};
```

### `page_entry` (hash table)
```c
struct page_entry {
    u32 hash;
    struct address_space *mapping;
    pgoff_t index;
    struct hlist_node node;
};
```
Stored in `oob_folio_hash` (4096-bucket hash table). Ephemeral — rebuilt each scan cycle.

### `file_dedup_slot` (queue)
```c
struct file_dedup_slot {
    struct address_space *mapping;
    pgoff_t pgoff;      // per-file scan cursor
    struct list_head list;
    struct hlist_node hash;
};
```

---

## 4. Modified Kernel Files

### Core dedup module
| File | Purpose |
|------|---------|
| [mm/oob_dedup.c](file:///Users/kshitij/Desktop/linux-oob-pagecache-dedup/mm/oob_dedup.c) | Scanner thread, hash table, deduplicate_folio, disconnect_folio, COW, sysfs, init |
| [mm/oob_dedup.h](file:///Users/kshitij/Desktop/linux-oob-pagecache-dedup/mm/oob_dedup.h) | Inline helpers: folio_test_dedup, folio_dedup_info, folio_shares_mapping, folio_index_in, folio_pos_near |
| [mm/file_dedup_slot.h](file:///Users/kshitij/Desktop/linux-oob-pagecache-dedup/mm/file_dedup_slot.h) | file_dedup_slot struct, alloc/free/lookup helpers |

### Modified kernel files
| File | What changed |
|------|-------------|
| [include/linux/page-flags.h](file:///Users/kshitij/Desktop/linux-oob-pagecache-dedup/include/linux/page-flags.h#L658) | Added `PAGE_MAPPING_DEDUP = 0x4` to `PAGE_MAPPING_FLAGS` |
| [mm/filemap.c](file:///Users/kshitij/Desktop/linux-oob-pagecache-dedup/mm/filemap.c) | Modified `page_cache_delete`, `page_cache_delete_batch`, `filemap_unaccount_folio`, `filemap_remove_folio`. Added `filemap_remove_folio_at`. Dedup-aware truncation, NR_FILE_PAGES dissolution fixes. |
| [mm/truncate.c](file:///Users/kshitij/Desktop/linux-oob-pagecache-dedup/mm/truncate.c) | Modified `truncate_inode_pages_range` to handle deduped folios (uses `folio_shares_mapping`, `folio_index_in`, `folio_pos_near`) |
| [mm/fadvise.c](file:///Users/kshitij/Desktop/linux-oob-pagecache-dedup/mm/fadvise.c) | Added `POSIX_FADV_DEDUP = 8` case to `fadvise64_64()` → calls `oob_dedup_add_file()` |
| [mm/Makefile](file:///Users/kshitij/Desktop/linux-oob-pagecache-dedup/mm/Makefile) | Added `oob_dedup.o` to build |

### Write path (COW hook)
The COW is triggered from the filesystem write path. When `generic_perform_write()` (or XFS equivalent) gets a folio for writing and `folio_test_dedup(folio)` is true, it calls `oob_folio_break_dedup()` which:
1. Allocates a new folio of the same order
2. Copies data from the shared folio
3. Swaps the XArray entry (xas_store)
4. Adds NR_FILE_PAGES for new_folio (does NOT subtract for old_folio — it's still live)
5. Removes the rmap entry, potentially dissolving the dedup

---

## 5. NR_FILE_PAGES Accounting Rules

> [!IMPORTANT]
> These rules are critical. Violations cause `Cached` in `/proc/meminfo` to underflow to 0.

### The Invariant
`NR_FILE_PAGES` counts **unique physical pages** in the page cache. A deduped folio serving 3 XArray entries counts as **1**, not 3.

### When to modify NR_FILE_PAGES

| Event | NR change | Code location |
|-------|-----------|---------------|
| Folio first enters cache | +nr | `__filemap_add_folio` |
| Dedup merges dup into orig | -nr (for dup_folio only) | `deduplicate_folio` line 265 |
| COW allocates new_folio | +nr (for new_folio only) | `oob_dedup_cow` line 1130 |
| COW: old_folio stays in cache | **NO CHANGE** | old_folio still at original entry |
| Normal folio leaves cache | -nr | `filemap_unaccount_folio` line 202 |
| Deduped folio: unaccount called | **SKIP** (returns early) | `filemap_unaccount_folio` line 169 |
| Intra-file dissolution (mapping=NULL) | -nr | dissolution fix in `page_cache_delete`, `page_cache_delete_batch`, `filemap_remove_folio_at` |
| Cross-file dissolution (mapping=other) | **NO CHANGE** here | surviving file's truncation handles it |

### Fixed Bugs (2026-04-25)
1. **COW old_folio decrement** — was subtracting NR for old_folio that's still alive. Leaked -N per COW cycle.
2. **Missing dissolution stat fix** — `page_cache_delete` and `page_cache_delete_batch` weren't decrementing NR after intra-file dissolution. Leaked +1 per dissolution.

### Verification
```bash
# Ground truth (independent of NR_FILE_PAGES):
grep MemFree /proc/meminfo     # Buddy allocator free count
cat /proc/buddyinfo             # Per-zone free pages

# Potentially corrupted if NR_FILE_PAGES is wrong:
grep ^Cached /proc/meminfo      # Derived from NR_FILE_PAGES
```

---

## 6. User-Space API

### Triggering Dedup
```c
#include <fcntl.h>
#define POSIX_FADV_DEDUP 8

int fd = open("file.dat", O_RDONLY);
posix_fadvise(fd, 0, 0, POSIX_FADV_DEDUP);  // Queue for dedup
close(fd);
```

### Sysfs Knobs (`/sys/kernel/oob_dedup/`)

| Knob | R/W | Default | Description |
|------|-----|---------|-------------|
| `files_queued` | R | - | Number of files currently queued |
| `pages_deduped` | R | - | Cumulative pages deduped |
| `pages_scanned` | R | - | Cumulative pages scanned |
| `folios_split` | R | - | Large folios split for partial match |
| `sleep_millisecs` | RW | 20 | Scanner sleep between rounds |
| `pages_to_scan` | RW | 4096 | Pages to scan per round |
| `merge_threshold_pct` | RW | 50 | Min % matching pages to trigger split |

---

## 7. Test Infrastructure

### Clean Tests (`tests/clean_tests/`)

Run via:
```bash
sudo bash run_clean_tests.sh
```

Key test files:
| Test | What it tests |
|------|--------------|
| `test_intra_file_dedup.c` | Same-inode dedup (multiple copies of same page in one file) |
| `test_cow_isolation_auto.c` | Write to deduped page triggers COW, original unchanged |
| `test_truncate_deduped.c` | rm/truncate of files with deduped pages |
| `test_cascade_unlink.c` | Delete chain: A→B→C where B is deduped with A |
| `test_fanout_cow.c` | Multiple files sharing one folio, COW on each |
| `test_rededup_after_cow.c` | Re-dedup after COW breaks sharing |
| `test_memory_savings.sh` | End-to-end memory savings measurement |
| `test_explicit_dedup_large_file.sh` | 200MB file dedup with metrics |
| `test_nr_file_pages_leak.c` | Detect NR_FILE_PAGES accounting leaks |

### Profile Tests (`tests/profile_tests/`)

```bash
sudo python3 run_profiling.py
```

Auto-detects XFS, creates files of sizes [32, 64, 128, ...] MB, measures:
- Dedup time (background scanner speed)
- Normal vs deduped read latency
- Normal vs deduped write latency (COW overhead)
- Generates `profiling_report.md`, `dedup_times.png`, `read_write_times.png`

---

## 8. VM Setup & Workflow

### XFS Loopback (for large folio support)
```bash
# Create 2GB XFS disk
sudo dd if=/dev/zero bs=1M count=2048 of=/opt/xfs_disk.img
sudo mkfs.xfs -f /opt/xfs_disk.img
sudo mount -o loop /opt/xfs_disk.img /mnt/xfs

# Verify
df -Th /mnt/xfs
```

### Build & Deploy
```bash
cd ~/linux-oob-pagecache-dedup
git pull
make -j$(nproc)
sudo make modules_install
sudo make install
sudo reboot
```

### Daily Workflow
```bash
# After boot
sudo mount -o loop /opt/xfs_disk.img /mnt/xfs

# Run clean tests
cd ~/linux-oob-pagecache-dedup/oob_pagecache_dedup_project/tests/clean_tests
sudo bash run_clean_tests.sh

# Run profiling
sudo python3 ../profile_tests/run_profiling.py

# Check dedup stats
cat /sys/kernel/oob_dedup/*

# Monitor memory
watch -n1 "grep MemFree /proc/meminfo"
```

---

## 9. Known Limitations & Gotchas

### Readahead + Deduped Folios Conflict
When readahead creates large folios (order-4) at an index where an order-0 deduped folio exists, `__filemap_get_folio` can enter an infinite loop. The inter-file shuffled test was removed for this reason.

**Workaround:** Disable readahead before verification reads:
```bash
echo 0 > /sys/block/sda/queue/read_ahead_kb
```

### Large Folio Hashing Limitation
Full-folio hashing means partial matches across large folios are never detected. Two 64KB folios sharing 15/16 pages have different CRC32 hashes. The `merge_threshold_pct` only applies AFTER a hash match (which never happens for partial matches).



### folio_trylock Contention
Scanner uses `folio_trylock` to avoid deadlocking with writeback. Under I/O load, many folios are locked by writeback → scanner gets EAGAIN → low dedup success rate.

### pr_info Overhead
`oob_dedup.c` has many `pr_info` calls that flood dmesg and slow down the scanner. Convert to `pr_debug` for production.

### Loopback Double-Caching
On loopback XFS (`mount -o loop`), pages exist in BOTH the XFS page cache and the ext4 page cache (backing the .img file). Only the XFS layer is deduped. Memory savings appear as ~50% of expected because the ext4 layer is untouchable.

### rm Truncation Performance
Truncating files with many deduped entries walks the rmap list per folio → O(n²) for files with N deduped pages. For large files, use `drop_caches` before `rm` to dissolve dedup first:
```bash
sync && echo 3 > /proc/sys/vm/drop_caches
rm -f deduped_file.dat
```

---

## 10. Critical Code Paths — Quick Reference

| Operation | Entry point | Key functions |
|-----------|-------------|---------------|
| Queue file for dedup | `fadvise64_64()` | `oob_dedup_add_file()` |
| Background scan | `oob_dedup_thread_fn()` | `oob_dedup_do_scan()` → `check_and_store_folio()` |
| Merge two folios | `deduplicate_folio()` | XArray swap, rmap setup, NR accounting |
| Disconnect on truncate | `oob_dedup_disconnect_folio()` | rmap removal, intra-file XArray cleanup, dissolution |
| COW on write | `oob_folio_break_dedup()` | Alloc new folio, copy, XArray swap, rmap removal |
| Check if folio is deduped | `folio_test_dedup()` | Bit check on `folio->mapping` |
| Get correct index for mapping | `folio_index_in()` | rmap list scan |
| Page cache removal (single) | `page_cache_delete()` | Disconnect + dissolution NR fix |
| Page cache removal (batch) | `page_cache_delete_batch()` | Disconnect + dissolution NR fix |
| Truncation-safe removal | `filemap_remove_folio_at()` | Explicit index, disconnect + dissolution NR fix |
