# OOB Page Cache Deduplication — Complete Project Context

> **Purpose**: This document captures every architectural detail, code path, data structure,
> bug fix, and test result needed to write a comprehensive research-paper-style LaTeX report.
> Hand this file (plus the report_plan.md) to another LLM/chat and it can produce the full report.

---

## 1. Project Overview

**Goal**: Implement an **out-of-band (OOB) background scanner** inside the Linux 6.8 kernel that identifies and merges identical page cache folios across (and within) files, reducing physical memory usage without changing on-disk data.

**Kernel version**: Linux 6.8 (custom fork)  
**Filesystem**: Tested primarily on XFS (large folio support) and ext4  
**Build**: `obj-y += oob_dedup.o` in `mm/Makefile` — always compiled in, no Kconfig gate  
**Entry point**: `subsys_initcall(oob_dedup_init)` — runs the `oob_dedupd` kernel thread at boot  

**Key files modified/added**:

| File | Role |
|------|------|
| `mm/oob_dedup.c` (1380 lines, NEW) | Core: scanner thread, anchor hashing, deduplicate_folio, COW break, disconnect, sysfs, evict |
| `mm/oob_dedup.h` (160 lines, NEW) | Data structures: `oob_dedup_info`, `oob_dedup_rmap_entry`, inline helpers (`folio_test_dedup`, `folio_dedup_info`, `folio_set_dedup_info`, `folio_index_in`, `folio_pos_in`, `folio_pos_near`, `folio_shares_mapping`, `folio_shares_index`) |
| `mm/file_dedup_slot.h` (56 lines, NEW) | `file_dedup_slot` struct and alloc/free/lookup/insert macros for the scanner work queue |
| `mm/filemap.c` (MODIFIED) | `page_cache_delete`, `filemap_unaccount_folio`, `filemap_remove_folio`, `filemap_remove_folio_at` (NEW), `page_cache_delete_batch`, `__filemap_get_folio` (FGP_STABLE guard), `filemap_get_read_batch` (retry guard) |
| `mm/truncate.c` (MODIFIED) | `folio_invalidate`, `truncate_inode_folio`, `truncate_inode_partial_folio`, `truncate_inode_pages_range` — all patched for dedup-aware removal |
| `mm/fadvise.c` (MODIFIED) | Added `POSIX_FADV_DEDUP` (value 8) case: sets `AS_DEDUPABLE` flag, calls `oob_dedup_add_file()` |
| `fs/iomap/buffered-io.c` (MODIFIED) | `iomap_write_begin`: COW hook — if `folio_test_dedup(folio)`, calls `oob_folio_break_dedup()` before writing |
| `fs/inode.c` (MODIFIED) | `evict()`: calls `oob_dedup_evict_inode()` to clean scan queue and hash table entries on inode death |
| `include/linux/pagemap.h` (MODIFIED) | Added `AS_DEDUPABLE` flag and helpers `mapping_set_dedupable`, `mapping_clear_dedupable`, `mapping_is_dedupable` |
| `include/linux/page-flags.h` (MODIFIED) | Added `PAGE_MAPPING_DEDUP` bit (value 0x4) to the `folio->mapping` tag space |

---

## 2. Architecture

### 2.1 User-Space Interface
- User opens a file read-only, calls `posix_fadvise(fd, 0, 0, POSIX_FADV_DEDUP)` (advice=8)
- Kernel sets `AS_DEDUPABLE` on the `address_space->flags`
- `oob_dedup_add_file(mapping)` allocates a `file_dedup_slot`, inserts into a global linked list (`file_dedup_list`) and hash table (`file_dedup_hash`), increments `stat_files_queued`, wakes the scanner thread

### 2.2 Scanner Thread (`oob_dedupd`)
- Kernel thread started at `subsys_initcall`, nice level 5
- Sleeps `sleep_millisecs` (default 20ms) between scan batches
- Each wakeup scans up to `pages_to_scan` (default 4096) pages
- **Round-robin fairness**: divides budget evenly across all queued files (`slot_budget = remaining / nslots`)
- Per-file cursor stored in `slot->pgoff`; when a file is fully scanned (`pgoff >= i_size/PAGE_SIZE`), the slot is removed from the queue
- Uses `igrab(inode)` to safely hold the inode during scan; skips dying inodes (BUG-13 fix)

### 2.3 Anchor-Based Hashing (Two-Level Scheme)
**Phase 1 — I/O Veto**: Skip dirty/writeback folios (retry next round)  
**Phase 2 — Zero-page short circuit**: If first page is all zeros, skip (prevents hash hot-bucket pathology)  
**Phase 3 — Anchor geometry**: `compute_anchor_geometry(nr_pages)`:
- `stride = (nr_pages * merge_threshold_pct) / 100` (default 50%)
- `anchor_count = nr_pages / stride`, capped at `MAX_ANCHORS=8`
- `evasion_off = stride/2 | 1` (odd offset to skip file headers)
- For order-0 folios: single full-page CRC32 hash
- For large folios: hash only anchor pages at positions `evasion_off + i*stride`

**Phase 4 — Hash table lookup**: For each anchor hash, search `oob_folio_hash` (4096-bucket hashtable). On first hit:
- Fetch candidate folio via `filemap_get_folio(entry_mapping, entry_index)`
- Do full page-by-page `memcmp` via `compare_folios_count()`
- If 100% match → call `deduplicate_folio()`
- If match >= `merge_threshold_pct` and folio is large and not already deduped → `split_folio()` then re-scan
- If no match → store all anchor hashes in the hash table for future candidates

### 2.4 Dedup State: Tagged Pointer Mechanism
- `folio->mapping` normally points to `address_space*`
- When deduped: `folio->mapping = (oob_dedup_info*) | PAGE_MAPPING_DEDUP` (bit 0x4)
- `folio_test_dedup(folio)`: checks `(folio->mapping & PAGE_MAPPING_FLAGS) == PAGE_MAPPING_DEDUP`
- `folio_dedup_info(folio)`: strips tag bits, returns `oob_dedup_info*`

### 2.5 Data Structures

```c
struct oob_dedup_info {
    spinlock_t lock;
    struct list_head rmap_list;   // list of oob_dedup_rmap_entry
    unsigned int rmap_count;      // number of entries
    struct hlist_node node;
} __attribute__((aligned(8)));    // alignment ensures tag bits are free

struct oob_dedup_rmap_entry {
    struct address_space *mapping; // owning file's address_space
    pgoff_t index;                 // XArray index in that mapping
    struct list_head list;
};

struct file_dedup_slot {
    struct hlist_node hash;
    struct list_head list;
    struct address_space *mapping;
    unsigned long pgoff;  // per-slot scan cursor
};

struct page_entry {  // hash table entry for anchor hashes
    u32 hash;
    struct address_space *mapping;
    pgoff_t index;
    unsigned int anchor_idx;
    struct hlist_node node;
};

struct oob_scan {  // global scanner cursor
    struct file_dedup_slot *slot;
    unsigned long pgoff;
    unsigned long seqnr;
};
```

---

## 3. Core Algorithms

### 3.1 `deduplicate_folio(orig_folio, dup_folio, mapping, index)` — Line 190
**Purpose**: Merge dup_folio into orig_folio. After this, both XArray slots point to orig_folio.

**Steps**:
1. **Pre-allocate** `dup_entry` (always), `new_info` + `orig_entry` (only if orig not already deduped) — avoids GFP_KERNEL under locks
2. **Trylock both folios** in address order (lower address first) — prevents deadlock with writeback path (`ext4_do_writepages → mpage_prepare_extent_to_map`)
3. **Safety checks**: both uptodate, neither dirty/writeback/mapped
4. **Strip private data**: `filemap_release_folio()` on both (removes XFS `iomap_folio_state`)
5. **Staleness check**: dup_folio still at expected mapping/index, orig_folio->mapping non-NULL
6. **Set up oob_dedup_info**: If orig not deduped, create info, add orig_entry with orig's mapping/index, set tagged pointer. If already deduped, extract existing info
7. **Add dup_entry** to rmap_list with dup's mapping/index
8. **XArray swap**: `xas_store(&xas, orig_folio)` in dup's mapping at base_index (aligned to folio order). Add `folio_nr_pages` refs to orig_folio
9. **On XAS error**: rollback — remove dup_entry, possibly dissolve info
10. **Accounting**: `NR_FILE_PAGES -= folio_nr_pages(dup_folio)` (the physical page is freed). Do NOT increment for orig (already counted)
11. **Orphan dup_folio**: `dup_folio->mapping = NULL`, isolate from LRU, uncharge memcg
12. **Unlock both**, increment `stat_pages_deduped`

### 3.2 `oob_dedup_disconnect_folio(folio, mapping, index)` — Line 784
**Purpose**: Remove one rmap entry during page cache removal (truncation/eviction).

**Steps**:
1. Extract `info = folio_dedup_info(folio)`
2. `spin_lock_irqsave(&info->lock)` (caller holds `xa_lock_irq`)
3. Walk rmap_list, match on **both** mapping AND index (critical for intra-file dedup)
4. Delete matched entry, decrement rmap_count
5. **If rmap_count == 1** (dissolution):
   - Last entry remains. If `last->mapping == mapping` (intra-file): clear the sibling XArray slot too, `folio->mapping = NULL` (folio leaves cache entirely), drop refs
   - If `last->mapping != mapping` (cross-file): `folio->mapping = last->mapping`, `folio->index = last->index` (folio survives in other file)
   - Free last entry and info struct
6. **If rmap_count == 0**: `folio->mapping = NULL`, free info

### 3.3 `oob_folio_break_dedup(mapping, foliop, pos, len)` — Line 1240
**Purpose**: Copy-on-Write. Called from `iomap_write_begin` when writing to a deduped folio.

**Steps**:
1. Compute base_index aligned to folio order
2. Allocate new_folio of same order, charge memcg
3. Set `new_folio->mapping = mapping`, `new_folio->index = index`
4. `folio_copy(new_folio, old_folio)` — byte-for-byte data copy
5. Lock new_folio, then `xas_lock_irq` + `spin_lock(&info->lock)`
6. Verify old_folio still in XArray (`xas_load`)
7. `xas_store(&xas, new_folio)` — swap in XArray
8. **Accounting**: `NR_FILE_PAGES += folio_nr_pages(new_folio)`. Do NOT decrement for old_folio (it's still live in another mapping)
9. `oob_rmap_remove(info, mapping, index, old_folio)` — remove this file's rmap entry, possibly dissolve
10. `folio_put(old_folio)`, add new_folio to LRU
11. Unlock old_folio, set `*foliop = new_folio`

### 3.4 `oob_dedup_evict_inode(inode)` — Line 1144
**Purpose**: Clean up scanner queue and hash table when an inode is being evicted.

**Steps**:
1. Remove `file_dedup_slot` from `file_dedup_list` and `file_dedup_hash` (advance scanner cursor if needed)
2. Remove all `page_entry` entries from `oob_folio_hash` where `entry->mapping == mapping`

---

## 4. Kernel Integration Points

### 4.1 filemap.c Changes

**`page_cache_delete`** (line 127): Uses `folio_index_in(folio, mapping)` instead of `folio->index` for XArray state. After XArray removal, if folio was deduped, calls `oob_dedup_disconnect_folio`. Conditionally decrements `NR_FILE_PAGES` based on dissolution outcome.

**`filemap_unaccount_folio`** (line 173): **Early return** if `folio_test_dedup(folio)` — NR_FILE_PAGES was already decremented when `deduplicate_folio()` orphaned the duplicate. Subtracting again would underflow.

**`filemap_remove_folio`** (line 377): For deduped folios, extracts mapping from `rmap_list` first entry (since `folio->mapping` is tagged).

**`filemap_remove_folio_at`** (line 292, NEW): Index-aware removal for intra-file dedup. Uses caller-provided index instead of `folio_index_in()` which would return the first rmap match.

**`page_cache_delete_batch`** (line 429): Uses `folio_index_in()` for XArray positioning. Calls `oob_dedup_disconnect_folio(folio, mapping, xas.xa_index)` for deduped folios.

**`__filemap_get_folio`** (line ~2103): FGP_STABLE guard skips `folio_wait_stable` for deduped folios.

### 4.2 truncate.c Changes

**`folio_invalidate`** (line 155): For deduped folios, extracts a valid mapping from rmap_list to find `a_ops->invalidate_folio`.

**`truncate_inode_folio`** (line 203): Uses `folio_shares_mapping()` instead of direct comparison. For deduped folios, temporarily swaps `folio->mapping` to the real mapping for cleanup, then restores.

**`truncate_inode_partial_folio`** (line 259): Uses `folio_pos_near()` for correct position calculation. Before splitting a deduped large folio, calls `oob_dedup_disconnect_folio` first (since `split_folio` dereferences `mapping->i_mmap_rwsem` which would GPF on a tagged pointer).

**`truncate_inode_pages_range`** (line 408): 
- **Pass 1**: Checks if batch contains any deduped folios. If yes, uses per-folio `filemap_remove_folio_at()` with correct indices instead of `delete_from_page_cache_batch()`.
- **Pass 2**: For deduped folios, uses `folio_shares_index()` to verify the rmap entry still exists. If dissolved by an earlier iteration, handles stale XArray entries by direct `xas_store(NULL)`.
- Includes infinite-loop detector (`loop2_spins > 400` → `pr_emerg_ratelimited`).

### 4.3 iomap/buffered-io.c Changes (line 775)
In `iomap_write_begin`: After acquiring folio via `__iomap_get_folio`, checks `folio_test_dedup(folio)`. If true, calls `oob_folio_break_dedup()` which returns a fresh private folio copy. Write proceeds on the new folio.

### 4.4 fadvise.c Changes (line 174)
New case `POSIX_FADV_DEDUP`: validates `FMODE_READ`, checks `f_mapping` and `a_ops`, sets `AS_DEDUPABLE` bit, calls `oob_dedup_add_file()`.

### 4.5 inode.c Changes (line 710)
In `evict()`: calls `oob_dedup_evict_inode(inode)` to clean up scanner state before the inode's page cache is torn down.

---

## 5. Sysfs Interface

Path: `/sys/kernel/oob_dedup/`

| Knob | R/W | Description |
|------|-----|-------------|
| `files_queued` | RO | Number of files currently in scan queue |
| `pages_scanned` | RO | Total pages examined by scanner |
| `pages_deduped` | RO | Total pages successfully merged |
| `folios_split` | RO | Large folios split for partial-match dedup |
| `sleep_millisecs` | RW | Scanner sleep interval (default 20) |
| `pages_to_scan` | RW | Pages per scan batch (default 4096) |
| `merge_threshold_pct` | RW | Minimum match % to trigger split (default 50, range 1-100) |

---

## 6. Memory Accounting — NR_FILE_PAGES

This was the **hardest correctness problem** in the project.

### The Invariant
`NR_FILE_PAGES` must reflect the number of **physical** pages backing the page cache. When two XArray slots share one physical folio, the stat should count it **once**.

### Accounting Rules
1. **deduplicate_folio**: Decrement NR_FILE_PAGES by `folio_nr_pages(dup_folio)` (one physical copy is freed)
2. **filemap_unaccount_folio**: Early return for deduped folios (skip the normal decrement)
3. **page_cache_delete / page_cache_delete_batch / filemap_remove_folio_at**: After `oob_dedup_disconnect_folio`, decrement NR_FILE_PAGES only if: `!folio_test_dedup(folio) && (folio->mapping == mapping || folio->mapping == NULL)` — i.e., the folio is leaving the cache entirely or dissolved to this same mapping
4. **oob_folio_break_dedup (COW)**: Increment NR_FILE_PAGES by `folio_nr_pages(new_folio)`. Do NOT decrement for old_folio (it's still live elsewhere)

### The Bug (NR_FILE_PAGES Underflow)
- **Symptom**: `/proc/meminfo` showed negative Cached values (displayed as huge numbers due to unsigned)
- **Root cause**: `filemap_unaccount_folio` was decrementing for deduped folios whose NR_FILE_PAGES had already been subtracted in `deduplicate_folio`
- **Fix**: Early return in `filemap_unaccount_folio` when `folio_test_dedup(folio)`

---

## 7. Concurrency & Locking

### Lock Ordering
```
inode->i_lock
  └─ xa_lock_irq(&mapping->i_pages)
       └─ info->lock (spin_lock_irqsave, since caller may hold xa_lock_irq)
```

### Deadlock Avoidance
- **Trylock in deduplicate_folio**: Uses `folio_trylock()` instead of `folio_lock()` to avoid deadlocking with writeback path (`ext4_do_writepages → folio_lock`)
- **Address-ordered locking**: Locks lower-address folio first
- **Pre-allocation**: All `kmem_cache_alloc` calls happen before acquiring any folio locks
- **IRQ-save for info->lock**: `oob_dedup_disconnect_folio` uses `spin_lock_irqsave` because it's called under `xa_lock_irq`

### Safety Mechanisms
- **I/O Veto**: Scanner skips dirty/writeback folios
- **Zero-page skip**: Prevents hash table hot-bucket pathology
- **igrab/iput**: Scanner safely holds inode reference during scan
- **Staleness checks**: Before dedup, verify folio is still at expected mapping/index
- **Private data stripping**: `filemap_release_folio()` removes filesystem metadata before sharing

---

## 8. Bug Chronicle (Lessons Learned)

### Bug 1: `rm` Hang on Intra-File Dedup
- **Symptom**: `rm` on a file with intra-file dedup hangs forever in `truncate_inode_pages_range`
- **Root cause**: `oob_dedup_disconnect_folio` matched rmap entries by mapping only. For intra-file dedup, all entries share the same mapping, so it removed the wrong entry. The XArray was left with a stale slot that truncation kept rediscovering.
- **Fix**: Match on both `mapping AND index` in disconnect. Also, when dissolving intra-file dedup (last entry has same mapping), clear the sibling XArray slot and decrement nrpages.

### Bug 2: NR_FILE_PAGES Underflow (Negative Cached)
- **Symptom**: `/proc/meminfo` Cached shows negative or huge values after dedup+delete cycles
- **Root cause**: Double-decrement — `deduplicate_folio` decremented NR for the orphaned dup, then `filemap_unaccount_folio` decremented again during page cache removal
- **Fix**: `filemap_unaccount_folio` early return for deduped folios. The correct decrement point is in `page_cache_delete` / `filemap_remove_folio_at` after dissolution

### Bug 3: Read-Path Infinite Loop
- **Symptom**: `cat` on deduped file hangs; `filemap_get_read_batch` loops forever
- **Root cause**: For multi-order deduped folios, `folio_try_get` + `xas_reload` would fail because the folio's index didn't match the XArray position (the folio was shared and its `folio->index` belonged to another file)
- **Fix**: Added retry-count guard in `filemap_get_read_batch`. Ensured `xas_set_order` in `deduplicate_folio` uses the base index aligned to folio order.

### Bug 4: GPF on Split of Deduped Large Folio
- **Symptom**: Kernel NULL pointer dereference in `split_folio` during truncation
- **Root cause**: `split_folio` dereferences `folio->mapping->i_mmap_rwsem`. For deduped folios, `folio->mapping` is a tagged pointer to `oob_dedup_info`, not a real `address_space`
- **Fix**: In `truncate_inode_partial_folio`, dissolve dedup first via `oob_dedup_disconnect_folio` before calling `split_folio`. If still deduped after disconnect, remove the folio entirely.

### Bug 5: Scanner Infinite Loop on Deduped Folios
- **Symptom**: Scanner stuck on same pgoff forever
- **Root cause**: For deduped folios, `folio_index(folio)` returns the *surviving owner's* index, not the index in the file being scanned. Using it to advance the cursor could jump backwards.
- **Fix**: Advance cursor from `slot->pgoff + nr` instead of `folio_start + nr` for deduped folios.

### Bug 6: Dying Inode Spin
- **Symptom**: Scanner stuck on a slot whose inode is being deleted
- **Root cause**: `igrab(inode)` returns NULL for dying inodes, but scanner didn't remove the slot
- **Fix** (BUG-13): If `igrab` fails, remove the slot from the queue and advance cursor

### Bug 7: XArray Order Mismatch
- **Symptom**: Dedup fails or creates inconsistent state for large folios
- **Root cause**: `deduplicate_folio` used raw `index` for XArray state, not aligned to folio order
- **Fix**: Compute `base_index = (index >> folio_order(dup_folio)) << folio_order(dup_folio)` and use `xas_set_order(&xas, base_index, folio_order(dup_folio))`

---

## 9. Test Suite

All tests in `oob_pagecache_dedup_project/tests/clean_tests/`. Run via `run_clean_tests.sh`.

| Test | File | What it validates | Status |
|------|------|-------------------|--------|
| COW Isolation | `test_cow_isolation_auto.c` | Write to deduped file doesn't leak to sibling | PASS |
| Truncate Deduped | `test_truncate_deduped.c` | Truncation of one deduped file, sibling survives | PASS |
| Intra-File Dedup | `test_intra_file_dedup.c` | Same-file duplicate pages merge; COW + truncation work | PASS |
| Rapid Dedup-Delete | `test_rapid_dedup_delete.c` | Create+dedup+delete in quick succession, no crash | PASS |
| Cascade Unlink | `test_cascade_unlink.c` | Delete files in chain, no orphaned folios | PASS |
| Large Folio | `test_large_folio.c` | Multi-order folio dedup on XFS | PASS |
| Fanout COW | `test_fanout_cow.c` | Multiple files sharing one folio, COW on each | PASS |
| Delete Then Read | `test_delete_then_read.c` | Read sibling after deleting one deduped file | PASS |
| NR_FILE_PAGES Leak | `test_nr_file_pages_leak.c` | Verify Cached doesn't go negative after dedup cycles | PASS |
| Sysfs Stats | `test_sysfs_stats_auto.c` | Verify sysfs counters increment correctly | PASS |
| Mixed Ops Torture | `test_mixed_ops_torture.c` | Inter+intra dedup + hole-punch + partial truncate + COW + delete | PASS |
| COW During Truncate | `test_cow_during_truncate.c` | Concurrent write during truncation of shared file | PASS |
| Concurrent Trunc+COW | `test_concurrent_trunc_cow.c` | Multi-threaded truncation + write stress | PASS |
| Partial Truncate | `test_partial_truncate_dedup.c` | Mid-page truncation boundaries with dedup | PASS |
| Re-dedup After COW | `test_rededup_after_cow.c` | After COW breaks sharing, re-queue and re-dedup | PASS |
| Anchor Stress | `test_anchor_stress.c` | 8 files with varying similarity (exact/near-miss/scattered/half/zero/alien/tiny), full lifecycle | PASS |
| Anchor Partial Match | `test_anchor_partial_match.c` | Partial-match detection and folio splitting | PASS |
| Memory Savings | `test_memory_savings.sh` | Verify /proc/meminfo Cached decreases after dedup | PASS |
| Large File Dedup | `test_large_file_dedup.sh` | 8MB+ files dedup correctly | PASS |

---

## 10. Profiling & Performance

### Profiling Tool
`oob_pagecache_dedup_project/tests/profile_tests/run_profiling.py` — Python script that:
1. Creates test files of varying sizes
2. Queues them for dedup via `posix_fadvise`
3. Polls sysfs counters to track scan progress
4. Measures read latency (deduped vs non-deduped) and COW write latency
5. Generates `dedup_performance_graph.png`

### Performance Graph Data (from dedup_performance_graph.png)
- **Pages Scanned**: ~47,000 over ~15 seconds
- **Pages Deduped**: ~4,000 (stabilizes after initial scan)
- **Files Queued**: Rises to 4, stays at 4 during scan, drops to 0 when complete
- **Scan Rate**: ~3,000 pages/second
- **Dedup Ratio**: ~8.5% of scanned pages were duplicates (in this test workload)

### Expected Performance Characteristics
- **Read latency**: Unchanged for deduped folios (same physical page, served from cache)
- **Write latency**: Higher for first write to deduped folio (COW: allocate + copy + XArray swap), subsequent writes normal
- **Memory savings**: Proportional to duplicate content. For N identical files of M pages each, saves (N-1)*M pages
- **Scanner CPU**: Configurable via `sleep_millisecs` and `pages_to_scan`. At default settings, scanner is very lightweight (~5% CPU during active scan, 0% when idle)

---

## 11. Comparison with KSM

| Aspect | KSM | OOB Page Cache Dedup |
|--------|-----|---------------------|
| Target | Anonymous pages (process memory) | Page cache (file-backed pages) |
| Trigger | `madvise(MADV_MERGEABLE)` | `posix_fadvise(POSIX_FADV_DEDUP)` |
| Mechanism | Stable/unstable trees, write-protect PTEs | XArray pointer swap, COW in iomap write path |
| COW | MMU fault handler | `oob_folio_break_dedup` in iomap |
| Hashing | Full-page hash into red-black trees | Anchor-based sampling into hash table |
| Large folios | No (page-level only) | Yes (order-aware, split if partial match) |
| Intra-file | N/A | Supported (same mapping, different indices) |

---

## 12. Future Work
- **mmap COW**: Currently only buffered write path has COW hook. mmap writes would need page fault handler integration
- **Cgroup-aware dedup**: Currently dedup is system-wide. Could be scoped to cgroups
- **NUMA placement**: Ensure deduped folio is placed on optimal NUMA node
- **Compression**: Combine with zswap-style compression for further savings
- **Async COW**: Pre-copy deduped folios on read to amortize COW latency
- **Persistent dedup metadata**: Survive reboots by storing dedup state on disk
