#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/pagemap.h>
#include "file_dedup_slot.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/crc32.h>

/* Global Queue and Thread Data */
static LIST_HEAD(file_dedup_list);
static DEFINE_HASHTABLE(file_dedup_hash, 10);
static struct kmem_cache *file_dedup_cache;
static DEFINE_SPINLOCK(file_dedup_lock);

static struct task_struct *oob_dedup_thread;
static DECLARE_WAIT_QUEUE_HEAD(oob_dedup_wait);

static unsigned int sleep_millisecs = 20;
static unsigned int pages_to_scan = 100;
#define MAX_PAGES_PER_FILE 1024

/* struct oob_scan - cursor for scanning */
struct oob_scan {
    struct file_dedup_slot *slot;
    unsigned long pgoff;   
    unsigned long seqnr;
};

static struct oob_scan oob_scan = {
    .slot = NULL,
    .pgoff = 0,
    .seqnr = 0,
};

static DEFINE_HASHTABLE(oob_folio_hash, 12);

/*
* store mapping and index instead of raw PFN
* to check if some page still exists in cache or is evicted.
*/
struct page_entry {
    u32 hash;
    struct address_space *mapping;
    pgoff_t index;
    struct hlist_node node;
};

static u32 hash_folio(struct folio *folio)
{
    void *addr;
    u32 hash;
    
    addr = kmap_local_folio(folio, 0);
    hash = crc32_le(~0, addr, PAGE_SIZE);
    kunmap_local(addr);
    
    return hash;
}

static bool compare_folios(struct folio *f1, struct folio *f2)
{
    void *addr1, *addr2;
    bool match = false;

    addr1 = kmap_local_folio(f1, 0);
    addr2 = kmap_local_folio(f2, 0);

    if (memcmp(addr1, addr2, PAGE_SIZE) == 0)
        match = true;

    kunmap_local(addr2);
    kunmap_local(addr1);

    return match;
}

static void clean_folio_hashtable(void)
{
    struct page_entry *entry;
    struct hlist_node *tmp;
    int bkt;

    hash_for_each_safe(oob_folio_hash, bkt, tmp, entry, node) {
        hash_del(&entry->node);
        kfree(entry);
    }
}

static void check_and_store_folio(struct folio *folio, struct address_space *mapping, pgoff_t index)
{   
    struct page_entry *entry;
    struct hlist_node *tmp;
    bool found = false;
    u32 hash = hash_folio(folio);

    hash_for_each_possible_safe(oob_folio_hash, entry, tmp, node, hash) {
        if (entry->hash == hash) {
            if (entry->mapping == mapping && entry->index == index) // matching against itself
                continue;

            struct folio *orig_folio = filemap_get_folio(entry->mapping, entry->index);
            
            if (!IS_ERR(orig_folio)) {
                if (compare_folios(orig_folio, folio)) {
                    pr_info("Exact duplicate verified!\n");
                    pr_info("Match -> Inode 1: %lu (Index %lu) | Inode 2: %lu (Index %lu)\n", 
                             entry->mapping->host->i_ino, entry->index,
                             mapping->host->i_ino, index);
                    found = true;
                }
                folio_put(orig_folio); 
                
                if (found) break; 
            } else {
                /* The old page was evicted by the kernel. Clean up the stale hash entry. */
                pr_debug("Stale hash entry detected for Inode %lu. Removing.\n", entry->mapping->host->i_ino);
                hash_del(&entry->node);
                kfree(entry);
            }
        }
    }

    if (!found) {
        entry = kmalloc(sizeof(struct page_entry), GFP_KERNEL);
        if (entry) {
            entry->hash = hash;
            entry->mapping = mapping;
            entry->index = index;
            hash_add(oob_folio_hash, &entry->node, hash);
        }
    }
}

static void oob_dedup_do_scan(void)
{
    struct file_dedup_slot *slot;
    struct folio *folio;
    unsigned int pages_done = 0;

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
            oob_scan.pgoff = 0;
            oob_scan.seqnr++;
        }

        slot = oob_scan.slot;
		struct inode *inode = slot->mapping->host;
		ihold(inode); // Increment ref count
		spin_unlock(&file_dedup_lock);
		
		folio = filemap_get_folio(slot->mapping, oob_scan.pgoff);
		if (!IS_ERR(folio)) {
			check_and_store_folio(folio, slot->mapping, oob_scan.pgoff);
			folio_put(folio);
		}

        pages_done++;
        oob_scan.pgoff++;

		unsigned long max_pages = i_size_read(inode) >> PAGE_SHIFT;
        if (oob_scan.pgoff >= max_pages || oob_scan.pgoff >= MAX_PAGES_PER_FILE) {
            spin_lock(&file_dedup_lock);
            oob_scan.slot = list_next_entry(slot, list);
            oob_scan.pgoff = 0;
            spin_unlock(&file_dedup_lock);
        }

        iput(inode); // Decrement ref count
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

	oob_dedup_thread = kthread_run(oob_dedup_thread_fn, NULL, "oob_dedupd");
	if (IS_ERR(oob_dedup_thread)) {
		err = PTR_ERR(oob_dedup_thread);
		printk(KERN_EMERG "OOB_DEDUP: kthread_run failed with err: %d\n", err);
		goto out_free_cache;
	}

	printk(KERN_EMERG "OOB_DEDUP: Initialization complete, thread running.\n");
	return 0;

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
            ihold(mapping->host);
			pr_info("oob_dedup: Queued file for dedup. Inode: %lu, Mapping: %p\n",mapping->host->i_ino, mapping);
            oob_dedup_wakeup();
        } else {
            err = -ENOMEM;
        }
    } else {
        pr_debug("oob_dedup: Mapping %p already in queue, skipping.\n", mapping);
    }
    spin_unlock(&file_dedup_lock);
    return err;
}

void oob_dedup_remove_file(struct address_space *mapping)
{
	struct file_dedup_slot *slot;

	spin_lock(&file_dedup_lock);
	slot = file_dedup_slot_lookup(file_dedup_hash, mapping);
	if (slot) {
		if (oob_scan.slot == slot) {
			oob_scan.slot = list_next_entry(slot, list);
			oob_scan.pgoff = 0;
		}

		list_del(&slot->list);
		hash_del(&slot->hash);
		iput(mapping->host);
		file_dedup_slot_free(file_dedup_cache, slot);
	}
	spin_unlock(&file_dedup_lock);
}

EXPORT_SYMBOL_GPL(oob_dedup_add_file);
EXPORT_SYMBOL_GPL(oob_dedup_remove_file);

subsys_initcall(oob_dedup_init);