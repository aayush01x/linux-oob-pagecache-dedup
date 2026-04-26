#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include "file_dedup_slot.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/crc32.h>
#include <linux/xarray.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/atomic.h>
#include "oob_dedup.h"
#include <linux/memcontrol.h>
#include "internal.h"

/* Global Queue and Thread Data */
static LIST_HEAD(file_dedup_list);
static DEFINE_HASHTABLE(file_dedup_hash, 10);
static struct kmem_cache *file_dedup_cache;
static DEFINE_SPINLOCK(file_dedup_lock);
static DEFINE_SPINLOCK(folio_hash_lock);
static struct task_struct *oob_dedup_thread;
static DECLARE_WAIT_QUEUE_HEAD(oob_dedup_wait);

static struct kmem_cache *rmap_entry_cache;
static struct kmem_cache *dedup_info_cache;

static unsigned int sleep_millisecs = 20;
static unsigned int pages_to_scan = 4096;
#define MAX_PAGES_PER_FILE 1048576
#define MAX_ANCHORS 8		/* CPU safety cap for anchor count */

/* sysfs kobject and counters for the sysfs layer */
static struct kobject *oob_dedup_kobj;

static atomic_t stat_files_queued = ATOMIC_INIT(0);
static atomic_t stat_pages_deduped = ATOMIC_INIT(0);
static atomic_t stat_pages_scanned = ATOMIC_INIT(0);
static atomic_t stat_folios_split = ATOMIC_INIT(0);

static unsigned int merge_threshold_pct = 50;

static struct oob_scan oob_scan = {
    .slot = NULL,
    .pgoff = 0,
    .seqnr = 0,
};

static DEFINE_HASHTABLE(oob_folio_hash, 12);


/* Legacy: full-folio hash, superseded by anchor hashing.
 * Kept for reference and debugging. */
static u32 __maybe_unused hash_folio(struct folio *folio)
{
	void *addr;
	u32 hash = ~0;
	long i, nr = folio_nr_pages(folio);

	for (i = 0; i < nr; i++) {
		addr = kmap_local_folio(folio, i * PAGE_SIZE);
		hash = crc32_le(hash, addr, PAGE_SIZE);
		kunmap_local(addr);
	}

	return hash;
}

/*
 * Hash a single page within a folio at a specific page offset.
 * Used by the anchor sampling algorithm.
 */
static u32 hash_page_at(struct folio *folio, unsigned int page_idx)
{
	void *addr;
	u32 hash;

	addr = kmap_local_folio(folio, (unsigned long)page_idx * PAGE_SIZE);
	hash = crc32_le(~0, addr, PAGE_SIZE);
	kunmap_local(addr);
	return hash;
}

/*
 * Returns true if the first page of the folio is entirely zeros.
 */
static bool folio_first_page_is_zero(struct folio *folio)
{
	void *addr;
	bool is_zero;

	addr = kmap_local_folio(folio, 0);
	is_zero = (memchr_inv(addr, 0, PAGE_SIZE) == NULL);
	kunmap_local(addr);
	return is_zero;
}

/*
 * Computes stride, anchor count, and evasion offset from the
 * merge_threshold_pct tunable and the folio's page count.
 */
struct anchor_geometry {
	unsigned int stride;		/* minimum contiguous match size */
	unsigned int anchor_count;	/* number of anchors to drop */
	unsigned int evasion_off;	/* odd offset to skip headers */
};

static struct anchor_geometry compute_anchor_geometry(unsigned int nr_pages)
{
	struct anchor_geometry geo;

	geo.stride = (nr_pages * merge_threshold_pct) / 100;
	if (geo.stride == 0)
		geo.stride = 1;

	geo.anchor_count = nr_pages / geo.stride;

	/* CPU safety cap */
	if (geo.anchor_count > MAX_ANCHORS) {
		geo.anchor_count = MAX_ANCHORS;
		geo.stride = nr_pages / (geo.anchor_count + 1);
		if (geo.stride == 0)
			geo.stride = 1;
	}

	/* At least 1 anchor */
	if (geo.anchor_count == 0)
		geo.anchor_count = 1;

	/* Evasion offset: half-stride, forced odd */
	geo.evasion_off = geo.stride / 2;
	if ((geo.evasion_off & 1) == 0)
		geo.evasion_off |= 1;

	/* Clamp: evasion offset must not push anchors beyond nr_pages */
	if (geo.evasion_off >= nr_pages)
		geo.evasion_off = 0;

	return geo;
}

static unsigned int compare_folios_count(struct folio *f1, struct folio *f2)
{
	long nr = folio_nr_pages(f1);
	unsigned int matched = 0;
	long i;

	for (i = 0; i < nr; i++) {
		void *a1 = kmap_local_folio(f1, i * PAGE_SIZE);
		void *a2 = kmap_local_folio(f2, i * PAGE_SIZE);
		if (memcmp(a1, a2, PAGE_SIZE) == 0)
			matched++;
		kunmap_local(a2);
		kunmap_local(a1);
	}
	return matched;
}

static void clean_folio_hashtable(void)
{
    struct page_entry *entry;
    struct hlist_node *tmp;
    int bkt;

    spin_lock(&folio_hash_lock);
    hash_for_each_safe(oob_folio_hash, bkt, tmp, entry, node) {
        hash_del(&entry->node);
        kfree(entry);
    }
    spin_unlock(&folio_hash_lock);
}

static int deduplicate_folio(struct folio *orig_folio, struct folio *dup_folio,
                              struct address_space *mapping, pgoff_t index)
{
    struct oob_dedup_info *info = NULL, *new_info = NULL;
    struct oob_dedup_rmap_entry *orig_entry = NULL, *dup_entry = NULL;
    pgoff_t base_index = (index >> folio_order(dup_folio)) << folio_order(dup_folio);

    XA_STATE(xas, &mapping->i_pages, base_index);
    xas_set_order(&xas, base_index, folio_order(dup_folio));
    int err = -ENOMEM;

    // preallocate the entries and the info struct before taking
    // the locks to avoid a pretty stupid deadlock
    dup_entry = kmem_cache_alloc(rmap_entry_cache, GFP_KERNEL);
    if (!dup_entry) return -ENOMEM;

    if (!folio_test_dedup(orig_folio)) {
        new_info = kmem_cache_alloc(dedup_info_cache, GFP_KERNEL);
        orig_entry = kmem_cache_alloc(rmap_entry_cache, GFP_KERNEL);
        if (!new_info || !orig_entry) goto out_free;
    }

    // acquire locks for the folios — use trylock to avoid deadlocking
    // with the writeback path (ext4_do_writepages -> mpage_prepare_extent_to_map)
    if (orig_folio < dup_folio) {
        if (!folio_trylock(orig_folio)) { err = -EAGAIN; goto out_free; }
        if (!folio_trylock(dup_folio))  { folio_unlock(orig_folio); err = -EAGAIN; goto out_free; }
    } else {
        if (!folio_trylock(dup_folio))  { err = -EAGAIN; goto out_free; }
        if (!folio_trylock(orig_folio)) { folio_unlock(dup_folio); err = -EAGAIN; goto out_free; }
    }

    if (!folio_test_uptodate(orig_folio) || !folio_test_uptodate(dup_folio) ||
        folio_test_dirty(orig_folio) || folio_test_dirty(dup_folio) ||
        folio_test_writeback(orig_folio) || folio_test_writeback(dup_folio) ||
        folio_mapped(orig_folio) || folio_mapped(dup_folio)) {
        err = -EBUSY;
        goto out_unlock;
    }

    /*
     * Strip any filesystem-specific private data (like XFS iomap_folio_state)
     * from both folios before sharing, to prevent cross-inode state confusion.
     */
    if (folio_has_private(orig_folio)) {
        if (!filemap_release_folio(orig_folio, GFP_KERNEL)) {
            err = -EBUSY;
            goto out_unlock;
        }
    }
    if (folio_has_private(dup_folio)) {
        if (!filemap_release_folio(dup_folio, GFP_KERNEL)) {
            err = -EBUSY;
            goto out_unlock;
        }
    }

    // a check to make sure that the dup_folio was not changed before deduplication 
    if (folio_mapping(dup_folio) != mapping || folio_index(dup_folio) != index) {
        err = -EAGAIN;
        goto out_unlock;
    }
    
    if (!orig_folio->mapping) {
        err = -ESTALE;
        goto out_unlock;
    }
    /*
     * setting up a new oob_dedup_info if the orig_folio is not already deduplicated
     * and also populating it with the entry
     * else we just extract the info struct 
     * */
    if (!folio_test_dedup(orig_folio)) {
        info = new_info;
        spin_lock_init(&info->lock);
        INIT_LIST_HEAD(&info->rmap_list);
        
        orig_entry->mapping = orig_folio->mapping;
        orig_entry->index = orig_folio->index;
        list_add(&orig_entry->list, &info->rmap_list);
        info->rmap_count = 1;
        
        folio_set_dedup_info(orig_folio, info);
        new_info = NULL; /* Consumed */
        orig_entry = NULL; 
    } else {
        info = folio_dedup_info(orig_folio);
    }

    // add the dup_entry to our info from the orig_folio
    dup_entry->mapping = mapping;
    dup_entry->index = index;
    spin_lock(&info->lock);
    list_add_tail(&dup_entry->list, &info->rmap_list);
    info->rmap_count++;
    spin_unlock(&info->lock);

    // setup the xarray of the dup_folio(its inode)
    /* Take folio_nr_pages refs — matching what __filemap_add_folio
     * does for normal page-cache entries.  This ensures
     * filemap_free_folio() can drop the correct number of refs
     * during truncation without special-casing dedup entries.
     */
    folio_ref_add(orig_folio, folio_nr_pages(orig_folio));
    xas_lock_irq(&xas);
    xas_store(&xas, orig_folio);
    if (xas_error(&xas)) {
        // xas_store failed
        xas_unlock_irq(&xas);
        folio_put_refs(orig_folio, folio_nr_pages(orig_folio));
        
        spin_lock(&info->lock);
        list_del(&dup_entry->list);
        info->rmap_count--;
        
        
        //if the orig_folio wasn't deduplicated before
        // need to return mapping to normal and free info and other struct
        bool dissolve_needed = (info->rmap_count == 1);
        spin_unlock(&info->lock);
        
        if (dissolve_needed){
			struct oob_dedup_rmap_entry *last_entry =
				list_first_entry(&info->rmap_list,
					struct oob_dedup_rmap_entry, list);
			orig_folio->mapping = last_entry->mapping;
			orig_folio->index = last_entry->index;
			
			list_del(&last_entry->list);
			kmem_cache_free(rmap_entry_cache, last_entry);
			kmem_cache_free(dedup_info_cache, info);
		}
        
        err = xas_error(&xas);
        goto out_unlock;
    }
    xas_unlock_irq(&xas);
    folio_put_refs(dup_folio, folio_nr_pages(dup_folio));
    lruvec_stat_mod_folio(dup_folio, NR_FILE_PAGES, -folio_nr_pages(dup_folio));
    if (folio_test_pmd_mappable(dup_folio))
        lruvec_stat_mod_folio(dup_folio, NR_FILE_THPS, -folio_nr_pages(dup_folio));


#ifdef CONFIG_MEMCG
    if (dup_folio->memcg_data) {
        mem_cgroup_uncharge(dup_folio);
    }
#endif
    
    if (folio_test_lru(dup_folio)) {
        if (folio_isolate_lru(dup_folio)) {
            /* isolate took a ref; drop it now */
            folio_put(dup_folio);
        }
    }

    // orphan the dup_folio
    dup_folio->mapping = NULL;
    dup_folio->index = 0;

    folio_unlock(dup_folio);
    folio_unlock(orig_folio);

    atomic_inc(&stat_pages_deduped);
    return 0;

out_unlock:
    folio_unlock(dup_folio);
    folio_unlock(orig_folio);
out_free:
    if (new_info) kmem_cache_free(dedup_info_cache, new_info);
    if (orig_entry) kmem_cache_free(rmap_entry_cache, orig_entry);
    if (dup_entry) kmem_cache_free(rmap_entry_cache, dup_entry);
    return err;

}

static void check_and_store_folio(struct folio *folio, struct address_space *mapping, pgoff_t index)
{
    struct page_entry *entry;
    struct hlist_node *tmp;
    bool found = false;
    int err = 1;
    long nr = folio_nr_pages(folio);
    unsigned int i;

    /* Phase 3: compute anchor geometry */
    struct anchor_geometry geo;
    unsigned int n_anchors;
    u32 anchor_hashes[MAX_ANCHORS];
    unsigned int anchor_positions[MAX_ANCHORS];

    if (nr <= 1) {
        /* Order-0 folio: single page, degenerate to full-page hash */
        n_anchors = 1;
        anchor_hashes[0] = hash_page_at(folio, 0);
        anchor_positions[0] = 0;
    } else {
        geo = compute_anchor_geometry(nr);
        n_anchors = geo.anchor_count;

        for (i = 0; i < n_anchors; i++) {
            unsigned int pos = geo.evasion_off + i * geo.stride;
            if (pos >= nr)
                pos = nr - 1;  /* clamp to last page */
            anchor_positions[i] = pos;
            anchor_hashes[i] = hash_page_at(folio, pos);
        }
    }

    /*
     * For each anchor hash, search the hash table for a candidate.
     * On the FIRST hit, fetch the candidate folio and do a full
     * page-by-page comparison. This uses anchors purely as a
     * cheap pre-filter (two-level scheme).
     */
    for (i = 0; i < n_anchors && !found; i++) {
        u32 hash = anchor_hashes[i];
        spin_lock(&folio_hash_lock);
        hash_for_each_possible_safe(oob_folio_hash, entry, tmp, node, hash) {
            if (entry->hash != hash)
                continue;
            /* Skip self-matches: same folio, same anchor position */
            if (entry->mapping == mapping && entry->index == index)
                continue;

            struct address_space *entry_mapping = entry->mapping;
            pgoff_t entry_index = entry->index;
            spin_unlock(&folio_hash_lock);

            struct folio *orig_folio = filemap_get_folio(entry_mapping, entry_index);

            if (!IS_ERR(orig_folio)) {
                if (orig_folio == folio) {
                    pr_debug("Folios already share physical memory. Skipping.\n");
                    folio_put(orig_folio);
                    spin_lock(&folio_hash_lock);
                    found = true;
                    break;
                }

                if (folio_order(orig_folio) == folio_order(folio)) {
                    unsigned int matched = compare_folios_count(orig_folio, folio);
                    if (matched == nr) {
                        pr_info("Exact duplicate verified! (anchor %u hit)\n", i);
                        pr_info("Match -> Inode 1: %lu (Index %lu) | Inode 2: %lu (Index %lu) | Order: %d\n",
                                 entry_mapping->host->i_ino, entry_index,
                                 mapping->host->i_ino, index, folio_order(folio));
                        err = deduplicate_folio(orig_folio, folio, mapping, index);
                        if (err == 0) {
                            pr_info("Folio deduped successfully\n");
                            found = true;
                        } else {
                            pr_info("Could not deduplicate folio with err code = %d", err);
                        }
                    } else if (nr > 1 && matched * 100 >= nr * merge_threshold_pct) {
                        /*
                         * Cannot split a deduped folio: its folio->mapping is a
                         * tagged pointer to oob_dedup_info, not a real
                         * address_space.  split_huge_page_to_list() dereferences
                         * folio->mapping->i_mmap_rwsem which would NULL-deref.
                         */
                        if (folio_test_dedup(folio)) {
                            pr_debug("Skipping split of already-deduped folio at pgoff %lu\n", index);
                        } else {
                            pr_info("Partial match >= threshold (%u/%lu) via anchor %u. Splitting.\n",
                                     matched, nr, i);
                            folio_lock(folio);
                            if (!split_folio(folio)) {
                                atomic_inc(&stat_folios_split);
                                pr_info("Successfully split large folio at pgoff %lu. Scanner will re-visit.\n",
                                        index);
                            } else {
                                pr_debug("Failed to split large folio.\n");
                            }
                            folio_unlock(folio);
                        }
                    }
                }
                folio_put(orig_folio);
            } else {
                spin_lock(&folio_hash_lock);
                pr_debug("Stale hash entry detected for Inode %lu. Removing.\n", entry_mapping->host->i_ino);
                hash_del(&entry->node);
                kfree(entry);
                spin_unlock(&folio_hash_lock);
            }

            spin_lock(&folio_hash_lock);
            if (found)
                break;
        }
        spin_unlock(&folio_hash_lock);
    }

    /*
     * No anchor matched any existing entry — store all anchors
     * so future folios can match against this one.
     */
    if (!found) {
        spin_lock(&folio_hash_lock);
        for (i = 0; i < n_anchors; i++) {
            entry = kmalloc(sizeof(struct page_entry), GFP_ATOMIC);
            if (entry) {
                entry->hash = anchor_hashes[i];
                entry->mapping = mapping;
                entry->index = index;
                entry->anchor_idx = anchor_positions[i];
                hash_add(oob_folio_hash, &entry->node, anchor_hashes[i]);
            }
        }
        spin_unlock(&folio_hash_lock);
    }
}

static void oob_dedup_do_scan(void)
{
    struct file_dedup_slot *slot;
    struct address_space *slot_mapping;
    struct folio *folio;
    unsigned int pages_done = 0;
    unsigned int nslots;
    unsigned int slot_budget;       /* pages this slot may consume per round */
    unsigned int slot_pages_done;   /* pages consumed from the current slot */

    while (pages_done < pages_to_scan) {
        cond_resched(); /* Let other processes run */

        if (kthread_should_stop())
            break;

        spin_lock(&file_dedup_lock);

        if (list_empty(&file_dedup_list)) {
            oob_scan.slot = NULL;
            spin_unlock(&file_dedup_lock);
            break;
        }

        if (!oob_scan.slot || list_is_head(&oob_scan.slot->list, &file_dedup_list)) {
            oob_scan.slot = list_first_entry(&file_dedup_list, struct file_dedup_slot, list);
            oob_scan.seqnr++;
        }

        /*
         * Round-robin fairness: divide the remaining global budget evenly
         * across all queued slots so that no single file monopolises a
         * full scan wakeup.  Each slot gets at least 1 page.
         */
        nslots = atomic_read(&stat_files_queued);
        slot_budget = (nslots > 1)
                      ? max(1u, (pages_to_scan - pages_done) / nslots)
                      : (pages_to_scan - pages_done);
        slot_pages_done = 0;

        slot = oob_scan.slot;
        /* BUG-11 fix: copy mapping under lock to avoid UAF after unlock */
        slot_mapping = slot->mapping;
        struct inode *inode = slot_mapping->host;
        inode = igrab(inode); /* Safely attempt to grab the inode */

        if (!inode) {
            struct file_dedup_slot *next = list_next_entry(slot, list);
            if (list_is_head(&next->list, &file_dedup_list))
                oob_scan.slot = NULL;
            else
                oob_scan.slot = next;

            list_del(&slot->list);
            hash_del(&slot->hash);
            atomic_dec(&stat_files_queued);
            file_dedup_slot_free(file_dedup_cache, slot);
            spin_unlock(&file_dedup_lock);
            continue;
        }
        spin_unlock(&file_dedup_lock);

        /* Scan pages from the current slot up to slot_budget pages.
         * Use slot->pgoff for per-file progress tracking.
         */
        while (slot_pages_done < slot_budget) {
            folio = filemap_get_folio(slot_mapping, slot->pgoff);
            if (!IS_ERR(folio)) {
                long nr = folio_nr_pages(folio);
                pgoff_t folio_start = folio_index(folio);

                pr_debug("OOB_DEDUP: [SCAN] found folio at pgoff %lu, order=%u nr=%lu inode=%lu\n",
                        folio_start, folio_order(folio), nr,
                        slot_mapping->host->i_ino);

                /*
                 * Skip folios that are already deduped
                 */
                if (folio_test_dedup(folio)) {
                    folio_put(folio);
                    /*
                     * Do NOT use folio_start (= folio_index) here.
                     * For deduped folios, folio->index belongs to the
                     * surviving rmap owner (e.g. the base file), not to
                     * the file we are currently scanning.  Using it
                     * would jump the cursor backwards, causing an
                     * infinite loop.  Advance from the current slot
                     * position instead.
                     */
                    slot->pgoff += nr;
                    slot_pages_done += nr;
                    pages_done += nr;
                    atomic_add(nr, &stat_pages_scanned);
                    continue;
                }

                if (folio_test_dirty(folio) ||
                    folio_test_writeback(folio)) {
                    folio_put(folio);
                    slot_pages_done += nr;
                    pages_done += nr;
                    atomic_add(nr, &stat_pages_scanned);
                    continue;
                }

                if (folio_first_page_is_zero(folio)) {
                    folio_put(folio);
                    slot->pgoff = folio_start + nr;
                    slot_pages_done += nr;
                    pages_done += nr;
                    atomic_add(nr, &stat_pages_scanned);
                    continue;
                }

                /*
                 * Snapshot the cursor before the call so we can detect
                 * whether the split path inside check_and_store_folio
                 * rewound slot->pgoff.
                 */
                pgoff_t pgoff_before = slot->pgoff;

                check_and_store_folio(folio, slot_mapping, folio_start);
                folio_put(folio);

                if (slot->pgoff != pgoff_before) {
                    /*
                     * Split path rewound the cursor to folio_start.
                     * Don't advance further; the scanner will revisit the
                     * now-order-0 pages on the next inner-loop iteration.
                     */
                } else {
                    /* Normal case: advance past this folio. */
                    slot->pgoff = folio_start + nr;
                }
                slot_pages_done += nr;
                pages_done += nr;
                atomic_add(nr, &stat_pages_scanned);
            } else {
                slot->pgoff++;
                slot_pages_done++;
                pages_done++;
                atomic_inc(&stat_pages_scanned);
            }

            unsigned long max_pages =
                    (i_size_read(inode) + PAGE_SIZE - 1) >> PAGE_SHIFT;
            if (slot->pgoff >= max_pages ||
                slot->pgoff >= MAX_PAGES_PER_FILE) {
                /* Finished this file — remove and advance to next slot. */
                spin_lock(&file_dedup_lock);
                struct file_dedup_slot *next = list_next_entry(slot, list);
                if (list_is_head(&next->list, &file_dedup_list))
                    oob_scan.slot = NULL;
                else
                    oob_scan.slot = next;

                list_del(&slot->list);
                hash_del(&slot->hash);
                atomic_dec(&stat_files_queued);
                file_dedup_slot_free(file_dedup_cache, slot);
                spin_unlock(&file_dedup_lock);
                /* slot is gone; break inner loop, outer loop will pick next */
                break;
            }

            if (pages_done >= pages_to_scan)
                break;
        }

        iput(inode);

        /*
         * Per-slot budget exhausted but file not yet finished: advance the
         * cursor to the next slot so the next wakeup starts there (round-robin).
         * The current slot's pgoff is preserved in slot->pgoff.
         */
        if (oob_scan.slot == slot) {
            spin_lock(&file_dedup_lock);
            if (!list_empty(&file_dedup_list)) {
                struct file_dedup_slot *next = list_next_entry(slot, list);
                oob_scan.slot = list_is_head(&next->list, &file_dedup_list)
                                ? list_first_entry(&file_dedup_list,
                                                   struct file_dedup_slot, list)
                                : next;
                /* pgoff is per-slot now — no reset needed */
            }
            spin_unlock(&file_dedup_lock);
        }
    }
}
static int oob_dedup_thread_fn(void *nothing)
{
	set_user_nice(current, 5);

	while (!kthread_should_stop()) {
		/* Check if there is work to do */
		if (!list_empty(&file_dedup_list)) {
			oob_dedup_do_scan();
		}

		/* Sleep until next batch or until woken up */
		wait_event_interruptible_timeout(oob_dedup_wait,
				kthread_should_stop(),
				msecs_to_jiffies(sleep_millisecs));
	}
	clean_folio_hashtable();
	return 0;
}

/* 
 * in case the kernel decides that the folio is not need in the page cache
 * the folio is removed from the page cahce 
 * hence we handle it here
 * see page_cache_delete in mm/filemap.c for more info 
 *
 * */
void oob_dedup_disconnect_folio(struct folio *folio, struct address_space *mapping,
                                pgoff_t index)
{
  struct oob_dedup_info *info = folio_dedup_info(folio);
  struct oob_dedup_rmap_entry *entry, *tmp;
  bool dissolve = false;
	unsigned long flags;

    // since the ancestor? function holds irqsave(non interruptible lock) we need to keep using irqsave locks
    spin_lock_irqsave(&info->lock, flags);
    list_for_each_entry_safe(entry, tmp, &info->rmap_list, list) {
        /*
         * Match on both mapping AND index. For intra-file dedup, all rmap
         * entries share the same mapping, so matching on mapping alone would
         * remove the wrong entry and desync the rmap list from the XArray.
         */
        if (entry->mapping == mapping && entry->index == index) {
            list_del(&entry->list);
            info->rmap_count--;
            kmem_cache_free(rmap_entry_cache, entry);
            break; 
        }
    }

    // last page remaining 
    if (info->rmap_count == 1) {
        struct oob_dedup_rmap_entry *last = list_first_entry(&info->rmap_list, 
                                           struct oob_dedup_rmap_entry, list);
        /*
         * Intra-file dedup fix: if the remaining rmap entry belongs to the
         * SAME mapping we are disconnecting from, the folio is still present
         * at the other XArray slot (last->index). We must remove it now,
         * otherwise truncate_inode_pages_range will rediscover it endlessly.
         * The caller holds xa_lock_irq(&mapping->i_pages) so this is safe.
         */
        if (last->mapping == mapping) {
            XA_STATE(xas_other, &mapping->i_pages, last->index);
            xas_set_order(&xas_other, last->index, folio_order(folio));
            xas_store(&xas_other, NULL);
            mapping->nrpages -= folio_nr_pages(folio);
            /*
             * Drop the refs held by the sibling XArray entry.
             * Both home entries (__filemap_add_folio) and dedup
             * entries (folio_ref_add in deduplicate_folio) hold
             * folio_nr_pages refs.  We can't call filemap_free_folio
             * here (inside xa_lock_irq), so use folio_put_refs.
             */
            folio_put_refs(folio, folio_nr_pages(folio));
            folio->mapping = NULL;
        } else {
            /* Cross-file dissolution: folio survives in the
             * other file's XArray. */
            folio->mapping = last->mapping;
        }
        folio->index = last->index;
        list_del(&last->list);
        kmem_cache_free(rmap_entry_cache, last);
        dissolve = true;
    } else if (info->rmap_count == 0) {
        folio->mapping = NULL;
        dissolve = true;
    }
	spin_unlock_irqrestore(&info->lock, flags);
    if (dissolve){
        kmem_cache_free(dedup_info_cache, info);
        }
}

/* sysfs attribute functions */
static ssize_t files_queued_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sysfs_emit(buf, "%d\n", atomic_read(&stat_files_queued));
}

static ssize_t pages_deduped_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sysfs_emit(buf, "%d\n", atomic_read(&stat_pages_deduped));
}

static ssize_t pages_scanned_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sysfs_emit(buf, "%d\n", atomic_read(&stat_pages_scanned));
}

static ssize_t folios_split_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sysfs_emit(buf, "%d\n", atomic_read(&stat_folios_split));
}

static ssize_t sleep_millisecs_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sysfs_emit(buf, "%u\n", sleep_millisecs);
}

static ssize_t sleep_millisecs_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    unsigned int val;
    if (kstrtouint(buf, 10, &val) == 0) {
        sleep_millisecs = val;
    }
    return count;
}

static ssize_t merge_threshold_pct_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sysfs_emit(buf, "%u\n", merge_threshold_pct);
}

static ssize_t merge_threshold_pct_store(struct kobject *kobj, struct kobj_attribute *attr,
                                         const char *buf, size_t count)
{
    unsigned int val;
    if (kstrtouint(buf, 10, &val) == 0) {
        if (val < 1)   val = 1;
        if (val > 100) val = 100;
        merge_threshold_pct = val;
    }
    return count;
}

static ssize_t pages_to_scan_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sysfs_emit(buf, "%u\n", pages_to_scan);
}

static ssize_t pages_to_scan_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    unsigned int val;
    if (kstrtouint(buf, 10, &val) == 0) {
        if (val < 1) val = 1;
        pages_to_scan = val;
    }
    return count;
}

static struct kobj_attribute files_queued_attr          = __ATTR_RO(files_queued);
static struct kobj_attribute pages_deduped_attr         = __ATTR_RO(pages_deduped);
static struct kobj_attribute pages_scanned_attr         = __ATTR_RO(pages_scanned);
static struct kobj_attribute folios_split_attr          = __ATTR_RO(folios_split);
static struct kobj_attribute sleep_millisecs_attr       = __ATTR_RW(sleep_millisecs);
static struct kobj_attribute merge_threshold_pct_attr   = __ATTR_RW(merge_threshold_pct);
static struct kobj_attribute pages_to_scan_attr         = __ATTR_RW(pages_to_scan);

static struct attribute *oob_dedup_attrs[] = {
    &files_queued_attr.attr,
    &pages_deduped_attr.attr,
    &pages_scanned_attr.attr,
    &folios_split_attr.attr,
    &sleep_millisecs_attr.attr,
    &merge_threshold_pct_attr.attr,
    &pages_to_scan_attr.attr,
    NULL,
};
ATTRIBUTE_GROUPS(oob_dedup); 

static int __init oob_dedup_init(void)
{
	printk(KERN_EMERG "OOB_DEDUP: Entering init function...\n");
	int err;
	hash_init(file_dedup_hash);
	hash_init(oob_folio_hash);

	file_dedup_cache = kmem_cache_create("file_dedup_slot",
                    sizeof(struct file_dedup_slot),
                    0, SLAB_PANIC, NULL);
    if (!file_dedup_cache){
        printk(KERN_EMERG "OOB_DEDUP: Cache creation failed!\n");
        return -ENOMEM;
    }

    // peer entry cache
    rmap_entry_cache = kmem_cache_create("oob_dedup_rmap_entry",
                        sizeof(struct oob_dedup_rmap_entry),
                        0, SLAB_PANIC, NULL);

    // info struct cache (byte aligned)
    dedup_info_cache = kmem_cache_create("oob_dedup_info",
                        sizeof(struct oob_dedup_info),
                        8, SLAB_PANIC, NULL);

    if (!rmap_entry_cache || !dedup_info_cache)
        return -ENOMEM;

    oob_dedup_kobj = kobject_create_and_add("oob_dedup", kernel_kobj);
    if (!oob_dedup_kobj) {
        printk(KERN_EMERG "OOB_DEDUP: Failed to create sysfs kobject\n");
        err = -ENOMEM;
        goto out_free_cache;
    }

    err = sysfs_create_groups(oob_dedup_kobj, oob_dedup_groups);
    if (err) {
        printk(KERN_EMERG "OOB_DEDUP: Failed to create sysfs groups\n");
        goto out_put_kobj;
    }

    oob_dedup_thread = kthread_run(oob_dedup_thread_fn, NULL, "oob_dedupd");
    if (IS_ERR(oob_dedup_thread)) {
        err = PTR_ERR(oob_dedup_thread);
        printk(KERN_EMERG "OOB_DEDUP: kthread_run failed with err: %d\n", err);
        goto out_remove_groups;
    }

    printk(KERN_INFO "OOB_DEDUP: Initialization complete, thread running.\n");
    return 0;

out_remove_groups:
    sysfs_remove_groups(oob_dedup_kobj, oob_dedup_groups);
out_put_kobj:
    kobject_put(oob_dedup_kobj);
out_free_cache:
    kmem_cache_destroy(file_dedup_cache);
    return err;
}

void oob_dedup_wakeup(void) {
    if (waitqueue_active(&oob_dedup_wait)) {
        wake_up_interruptible(&oob_dedup_wait);
    }
}

int oob_dedup_add_file(struct address_space *mapping)
{
    struct file_dedup_slot *slot;
    int err = 0;

    spin_lock(&file_dedup_lock);
    slot = file_dedup_slot_lookup(file_dedup_hash, mapping);
    if (!slot) {
        slot = file_dedup_slot_alloc(file_dedup_cache);
        if (slot) {
            file_dedup_slot_insert(file_dedup_hash, mapping, slot);
            list_add_tail(&slot->list, &file_dedup_list);
            atomic_inc(&stat_files_queued);
			pr_info("OOB_DEDUP: Queued file for dedup. Inode: %lu, Mapping: %p\n",mapping->host->i_ino, mapping);
            oob_dedup_wakeup();
        } else {
            err = -ENOMEM;
        }
    } else {
        pr_debug("OOB_DEDUP: Mapping %p already in queue, skipping.\n", mapping);
    }
    spin_unlock(&file_dedup_lock);
    return err;
}

int oob_dedup_evict_inode(struct inode *inode)
{
    pr_debug("OOB_DEDUP: ENTERING EVICT NODE FUCTION\n");
    struct address_space *mapping = inode->i_mapping;
    struct file_dedup_slot *slot;
    struct page_entry *entry;
    struct hlist_node *tmp;
    int bkt;

    /* we only clean the scan queue */
    spin_lock(&file_dedup_lock);
    if (mapping) {
        slot = file_dedup_slot_lookup(file_dedup_hash, mapping);
        if (slot) {
            /* handle the case if we are scanning the file itself */
            if (oob_scan.slot == slot) {
                struct file_dedup_slot *next = list_next_entry(slot, list);
                if (list_is_head(&next->list, &file_dedup_list))
                    oob_scan.slot = NULL;
                else
                    oob_scan.slot = next;
            }

            list_del(&slot->list);
            hash_del(&slot->hash);
            atomic_dec(&stat_files_queued);
            file_dedup_slot_free(file_dedup_cache, slot);
        }
    }
    spin_unlock(&file_dedup_lock);

    /* remove the folio from the hash */
    spin_lock(&folio_hash_lock);
    hash_for_each_safe(oob_folio_hash, bkt, tmp, entry, node) {
        if (entry->mapping == mapping) {
            hash_del(&entry->node);
            kfree(entry);
        }
    }
    spin_unlock(&folio_hash_lock);

    
    return 0;
}


//enters with a  spin lock on info so can't dissolve it here
bool oob_rmap_remove(struct oob_dedup_info *info, struct address_space *mapping, 
                     pgoff_t index, struct folio* folio)
{
	pr_debug("OOB_DEDUP: entering rmap remove\n");
    struct oob_dedup_rmap_entry *slot, *tmp;
    bool found = false;
    bool dissolve = false;
    list_for_each_entry_safe(slot, tmp, &info->rmap_list, list) {
        if (slot->mapping == mapping && slot->index == index) {
            list_del(&slot->list);
            info->rmap_count--;
            kmem_cache_free(rmap_entry_cache, slot);
            found = true;
            break; 
        }
    }

    if (unlikely(!found)) {
        pr_warn("OOB_DEDUP: Attempted to remove non-existent rmap slot for Inode %lu\n",
                mapping->host->i_ino);
        return false;
    }


    if (info->rmap_count == 1) {
        struct oob_dedup_rmap_entry *last = list_first_entry(&info->rmap_list, 
                                           struct oob_dedup_rmap_entry, list);
        
        folio->mapping = last->mapping;
        folio->index = last->index;
        list_del(&last->list);
        kmem_cache_free(rmap_entry_cache, last);
        dissolve = true;
    }
	return dissolve;
}



int oob_folio_break_dedup(struct address_space *mapping, struct folio **foliop, 
                          loff_t pos, size_t len)
{
    struct folio *old_folio = *foliop;
    struct folio *new_folio = NULL;
    struct oob_dedup_info *info = folio_dedup_info(old_folio);
    int __maybe_unused err = 0;
    unsigned long old_pfn ;
    unsigned long new_pfn ;
    bool dissolve = false;

    // base index calculation
    pgoff_t index = (pos >> PAGE_SHIFT) & ~((1UL << folio_order(old_folio)) - 1);
    XA_STATE(xas, &mapping->i_pages, index);

    // allocate folio of same order 
    new_folio = filemap_alloc_folio(mapping_gfp_mask(mapping), folio_order(old_folio));
    if (!new_folio)
        return -ENOMEM;

#ifdef CONFIG_MEMCG
    err = mem_cgroup_charge(new_folio, NULL, mapping_gfp_mask(mapping));
    if (err) {
        folio_put(new_folio);
        return err;
    }
#endif

    new_folio->mapping = mapping;
    new_folio->index = index;
    // copy the folio and data
    folio_copy(new_folio, old_folio);
    pr_debug("OOB_DEDUP: COW break: copied folio data\n");
    __folio_mark_uptodate(new_folio);

    folio_lock(new_folio);

    // swap the pointers in the x-array
    
    xas_lock_irq(&xas);
    spin_lock(&info->lock);

    // if old folio replaced  
    if (unlikely(xas_load(&xas) != old_folio)) {
        xas_unlock_irq(&xas);
        spin_unlock(&info->lock);
        folio_unlock(new_folio);
        folio_put(new_folio);
        return -EAGAIN;
    }

	pr_debug("OOB_DEDUP: COW break: old refcount %d, new refcount %d\n",
		 folio_ref_count(old_folio), folio_ref_count(new_folio));

    old_pfn = folio_pfn(old_folio);
    new_pfn = folio_pfn(new_folio);
    xas_set_order(&xas, index, folio_order(new_folio));
    xas_store(&xas, new_folio);
    if (xas_error(&xas)) {
        pr_warn("OOB_DEDUP: COW break xas_store failed\n");
        spin_unlock(&info->lock);
        xas_unlock_irq(&xas);
        folio_unlock(new_folio);
        folio_put(new_folio);
        return xas_error(&xas);
    }

    __lruvec_stat_mod_folio(new_folio, NR_FILE_PAGES, folio_nr_pages(new_folio));
    if (folio_test_pmd_mappable(new_folio))
        __lruvec_stat_mod_folio(new_folio, NR_FILE_THPS, folio_nr_pages(new_folio));

    pr_debug("OOB_DEDUP: [SUCCESS] COW break PFN %lx -> %lx at index %lu\n",
             old_pfn, new_pfn, index);


    // remove the info about the folio from the list
    dissolve = oob_rmap_remove(info, mapping, index, old_folio);

    spin_unlock(&info->lock);
    xas_unlock_irq(&xas);

    if (dissolve)
        kmem_cache_free(dedup_info_cache, info);

    /* Add new_folio to LRU — alloc gave us 1 ref, xas_store holds it in
     * the page cache.  No extra folio_get needed. */
    folio_add_lru(new_folio);

    /*
     * Drop the page-cache refs that the old dedup XArray entry held.
     * deduplicate_folio() added folio_nr_pages refs when it stored
     * old_folio into this mapping's XArray.  xas_store(new_folio)
     * replaced the entry but does not drop those refs automatically.
     */
    folio_put_refs(old_folio, folio_nr_pages(old_folio));

    /* Unlock old_folio — the caller locked it via __filemap_get_folio.
     * Must unlock BEFORE the final put in case this put frees it. */
    folio_unlock(old_folio);

    /* Drop the caller's lookup reference on old_folio */
    folio_put(old_folio);

    *foliop = new_folio;
    return 0;
}


EXPORT_SYMBOL_GPL(oob_dedup_add_file);
EXPORT_SYMBOL_GPL(oob_dedup_evict_inode);
EXPORT_SYMBOL_GPL(oob_folio_break_dedup);
subsys_initcall(oob_dedup_init);

