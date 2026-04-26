# OOB Page Cache Deduplication — LaTeX Report Plan

> **Instructions for report writer**: Use `report_context.md` as the sole source of truth.
> Write a single `report.tex` file using `\documentclass{article}` with the sections below.
> Use `tikz` for architecture diagrams and flowcharts. Use `listings` for code snippets.
> Use `booktabs` for tables. Target ~20-25 pages.



## Section-by-Section Plan

### 1. Title Page & Abstract
- **Title**: "Out-of-Band Page Cache Deduplication in the Linux Kernel"
- **Abstract**: 150 words. State the problem (redundant file data in page cache wastes RAM), the approach (background kernel thread with anchor-based hashing), key results (test suite passes, memory savings demonstrated), and contribution (first OOB page cache dedup implementation with intra-file support and COW)

### 2. Introduction
- **Motivation**: Servers with many identical files (containers, VMs, package caches) waste RAM on duplicate page cache entries. Unlike KSM (anonymous pages), no existing mechanism deduplicates file-backed pages.
- **Problem statement**: Design a safe, non-intrusive mechanism to merge identical page cache folios without modifying on-disk data or existing filesystem code.
- **Contributions** (bullet list):
  1. OOB scanner architecture with fadvise-based opt-in
  2. Anchor-based hashing for efficient large folio comparison
  3. Symmetric rmap-based dedup state with tagged pointers
  4. COW mechanism integrated into iomap write path
  5. Intra-file dedup support with index-aware dissolution
  6. Comprehensive test suite and profiling framework
- **Paper organization**: Brief paragraph listing remaining sections

### 3. Background & Related Work
- **Linux Page Cache**: Explain address_space, XArray, folios (multi-order), folio->mapping
- **KSM**: How it works, why it doesn't cover page cache. Table comparing KSM vs our approach (from context doc Section 11)
- **Large folios**: Linux 6.x trend toward multi-order folios. Why this complicates dedup (order-aware XArray operations, can't split deduped folios directly).

### 4. System Architecture
**Include a TikZ architecture diagram** showing:
- User space: `posix_fadvise(POSIX_FADV_DEDUP)` → fadvise.c
- Kernel: Scanner thread loop → Anchor hashing → Hash table → deduplicate_folio
- Data flow: file_dedup_slot queue → round-robin scan → page_entry hash table → folio comparison → XArray swap
- Integration points: filemap.c (disconnect), truncate.c (removal), iomap/buffered-io.c (COW), inode.c (evict)

**Sub-sections**:
- 4.1 User-Space Interface (fadvise hook, AS_DEDUPABLE flag)
- 4.2 Scanner Thread (oob_dedupd, round-robin, per-slot cursor, igrab safety)
- 4.3 Anchor-Based Hashing (phases 1-4: veto → zero-skip → geometry → lookup/store)
- 4.4 Dedup State Representation (tagged pointer in folio->mapping, oob_dedup_info, rmap_list)
- 4.5 Sysfs Monitoring (table of knobs from context Section 5)

### 5. Design Decisions 
Justify key choices with alternatives considered:

| Decision | Choice | Alternative | Why |
|----------|--------|-------------|-----|
| Scanning model | Out-of-band background thread | Inline during page fault | Non-intrusive, no latency impact on hot path |
| Hashing | Anchor sampling + full verify | Full-folio CRC32 | O(k) vs O(n) for large folios; anchors catch partial matches |
| Dedup state | Tagged pointer in folio->mapping | Separate hash table | Zero per-folio overhead for non-deduped folios |
| Locking | folio_trylock + address order | folio_lock | Avoids deadlock with writeback path |
| rmap design | Linked list per info struct | Array or rb-tree | Simple, low expected count (2-5 entries) |
| Intra-file | Supported via index-aware rmap | Disallow | Important for files with repeated blocks (e.g., sparse images) |

### 6. Implementation Details
- 6.1 Data Structures: Show struct definitions (from context Section 2.5). Explain alignment requirement for tagged pointer. Explain kmem_cache usage for slab allocation.
- 6.2 Core Functions: Brief descriptions (not full code walks) of `deduplicate_folio`, `oob_dedup_disconnect_folio`, `oob_folio_break_dedup`, `oob_dedup_evict_inode`. Reference line numbers in oob_dedup.c.
- 6.3 Kernel Integration: For each modified file (filemap.c, truncate.c, iomap/buffered-io.c, fadvise.c, inode.c), explain what was changed and why. Use code snippets for critical 5-10 line sections.

### 7. Core Algorithm Flowcharts
**Three TikZ flowcharts**:

1. **Scanner Main Loop** (`oob_dedup_do_scan`):
   ```
   Start → Check queue empty? → Select slot (round-robin) → igrab(inode) →
   Get folio → Deduped? skip → Dirty/WB? skip → Zero? skip →
   Compute anchors → Search hash table → Match? → Full compare →
   100% match? → deduplicate_folio → Advance cursor → Budget exhausted? →
   File done? remove slot → Next slot
   ```

2. **Deduplication** (`deduplicate_folio`):
   ```
   Pre-allocate entries → Trylock both folios → Safety checks →
   Setup oob_dedup_info → Add rmap entry → XArray store →
   Success? → Decrement NR_FILE_PAGES → Orphan dup → Done
   Failure? → Rollback → Free allocations
   ```

3. **Dissolution** (`oob_dedup_disconnect_folio`):
   ```
   Get info → Lock → Find rmap entry (mapping+index) → Delete →
   rmap_count==1? → Same mapping? → Clear sibling XArray → folio->mapping=NULL
                  → Different mapping? → folio->mapping=last->mapping
   rmap_count==0? → folio->mapping=NULL
   Free info if dissolved
   ```

### 8. Memory Accounting
- Explain the NR_FILE_PAGES invariant (context Section 6)
- Show the accounting flow for each operation in a table:

| Operation | NR_FILE_PAGES change | Why |
|-----------|---------------------|-----|
| deduplicate_folio | -nr (for dup) | Physical page freed |
| filemap_unaccount_folio (deduped) | 0 (early return) | Already decremented |
| page_cache_delete (dissolution, same mapping) | -nr | Folio leaving cache |
| page_cache_delete (dissolution, cross mapping) | 0 | Folio still live |
| oob_folio_break_dedup | +nr (for new) | New physical page allocated |

- Describe the underflow bug and fix (context Section 8, Bug 2)

### 9. Concurrency & Safety 
- Lock ordering diagram (context Section 7)
- Deadlock avoidance strategy (trylock, pre-allocation, address ordering)
- IRQ-save requirement for info->lock
- I/O veto mechanism
- Race condition analysis: scanner vs truncation vs write

### 10. Testing & Validation
- Test infrastructure: `run_clean_tests.sh`, `common.c`/`common.h` helper
- **Table of all 19 tests** (from context Section 9) with columns: Test Name, File, Scenario, Key Assertion, Status
- Highlight the most important tests with brief descriptions:
  - Mixed Ops Torture (combines every edge case)
  - Anchor Stress (8 files with varying similarity, full lifecycle)
  - NR_FILE_PAGES Leak (accounting correctness)
  - Concurrent Trunc+COW (concurrency stress)

### 11. Experimental Results
- **Include the performance graph** (`dedup_performance_graph.png`)
- Interpret the graph: scan rate, dedup rate, queue lifecycle
- Discuss profiling methodology (`run_profiling.py`)
- Expected performance characteristics:
  - Read latency: unchanged
  - Write latency: one-time COW overhead
  - Memory savings: (N-1)*M for N identical files of M pages
  - Scanner CPU overhead

### 12. Lessons Learned & Bug Chronicle
- Present as a **timeline/table** of 7 critical bugs (from context Section 8)
- For each bug: Symptom → Root Cause → Fix → Lesson
- Group by category: XArray management, Memory accounting, Locking, Scanner logic
- Key takeaway paragraphs:
  1. "Dedup touches every page cache removal path" — the blast radius of sharing folio->mapping
  2. "Intra-file dedup is fundamentally harder" — same mapping breaks all assumptions
  3. "Memory accounting must be provably correct" — one wrong decrement = system-wide stat corruption

### 13. Future Work 
- From context Section 12: mmap COW, cgroup-aware, NUMA, compression, async COW, persistent metadata

### 14. Conclusion 
- Summarize contributions
- State that all 19 tests pass
- Emphasize the practical applicability (container/VM environments)

---

## Figures to Create (TikZ)

1. **System Architecture Diagram** — boxes for user space, fadvise hook, scanner thread, hash table, XArray, integration points
2. **Scanner Flowchart** — decision tree for the scan loop
3. **Deduplication Flowchart** — steps of deduplicate_folio
4. **Dissolution Flowchart** — oob_dedup_disconnect_folio logic
5. **Memory State Diagram** — before/after dedup showing two XArray slots → one physical folio
6. **COW Diagram** — showing the break_dedup allocation and swap

## Tables to Include

1. Modified kernel files (from context Section 1)
2. KSM comparison (from context Section 11)
3. Design decisions (from Section 5 above)
4. Sysfs knobs (from context Section 5)
5. NR_FILE_PAGES accounting (from Section 8 above)
6. Test suite (from context Section 9)
7. Bug chronicle (from context Section 8)

## Code Listings to Include (short, 5-15 lines each)

1. `folio_test_dedup` and `folio_set_dedup_info` inline helpers
2. Anchor geometry computation (key lines)
3. The XArray swap in `deduplicate_folio` (lines 296-334)
4. The rmap matching in `oob_dedup_disconnect_folio` (lines 794-806)
5. The COW hook in `iomap_write_begin` (lines 775-783)
6. The `filemap_unaccount_folio` early return (lines 183-184)
