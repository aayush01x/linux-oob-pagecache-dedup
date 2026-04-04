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
#include <linux/xarray.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/atomic.h>

/* Global Queue and Thread Data */
static LIST_HEAD(file_dedup_list);
static DEFINE_HASHTABLE(file_dedup_hash, 10);
static struct kmem_cache *file_dedup_cache;
static DEFINE_SPINLOCK(file_dedup_lock);
static DEFINE_SPINLOCK(folio_hash_lock);
static struct task_struct *oob_dedup_thread;
static DECLARE_WAIT_QUEUE_HEAD(oob_dedup_wait);

static unsigned int sleep_millisecs = 20;
static unsigned int pages_to_scan = 100;
#define MAX_PAGES_PER_FILE 1024

/* Order N merge threshold % (if >= this % pages match, split & merge) */
static unsigned int merge_threshold_pct = 50;
module_param(merge_threshold_pct, uint, 0644);
MODULE_PARM_DESC(
	merge_threshold_pct,
	"Percentage of identical pages required to split and merge a large folio");

/* sysfs kobject and counters for the sysfs layer */
static struct kobject *oob_dedup_kobj;

static atomic_t stat_files_queued = ATOMIC_INIT(0);
static atomic_t stat_pages_deduped = ATOMIC_INIT(0);
static atomic_t stat_pages_scanned = ATOMIC_INIT(0);
static atomic_t stat_folios_split = ATOMIC_INIT(0);

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
 * Compare two folios page-by-page. Both must be of the same order.
 * Returns the number of matching pages (0..nr_pages).
 */
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

static bool compare_folios(struct folio *f1, struct folio *f2)
{
	return compare_folios_count(f1, f2) == folio_nr_pages(f1);
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
	int err = 0;

	folio_lock(dup_folio);

	if (folio_mapping(dup_folio) != mapping ||
	    folio_index(dup_folio) != index) {
		pr_debug("Folio changed before removal. Aborting.\n");
		err = -EAGAIN;
		goto out;
	}

	/*
	 * NOTE: Actual XArray folio replacement is disabled.
	 * Storing orig_folio (with folio->index from a different position)
	 * into the target XArray slot breaks filemap_read(), which uses
	 * folio->index for offset calculations.
	 *
	 * The Symmetric Peer Model (PAGE_MAPPING_DEDUP + oob_dedup_info)
	 * is required before real merging can work. For now, we just
	 * detect and count dedup-eligible pages.
	 */
	atomic_inc(&stat_pages_deduped);
	pr_info("Detected duplicate folio at index %lu (counting only)\n",
		index);

out:
	folio_unlock(dup_folio);
	return err;
}

static void check_and_store_folio(struct folio *folio,
				  struct address_space *mapping, pgoff_t index)
{
	struct page_entry *entry;
	struct hlist_node *tmp;
	bool found = false;
	u32 hash = hash_folio(folio);

	spin_lock(&folio_hash_lock);
	hash_for_each_possible_safe(oob_folio_hash, entry, tmp, node, hash) {
		if (entry->hash != hash)
			continue;
		if (entry->mapping == mapping && entry->index == index)
			continue;

		struct address_space *entry_mapping = entry->mapping;
		pgoff_t entry_index = entry->index;
		spin_unlock(&folio_hash_lock);

		struct folio *orig_folio =
			filemap_get_folio(entry_mapping, entry_index);

		if (!IS_ERR(orig_folio)) {
			if (orig_folio == folio) {
				pr_debug(
					"Folios already share physical memory. Skipping.\n");
				folio_put(orig_folio);
				spin_lock(&folio_hash_lock);
				found = true;
				break;
			}

			if (folio_order(orig_folio) == folio_order(folio)) {
				long nr = folio_nr_pages(folio);
				unsigned int matched =
					compare_folios_count(orig_folio, folio);

				if (matched == nr) {
					pr_info("Exact duplicate verified!\n");
					pr_info("Match -> Inode 1: %lu (Index %lu) | Inode 2: %lu (Index %lu)\n",
						entry_mapping->host->i_ino,
						entry_index,
						mapping->host->i_ino, index);
					if (deduplicate_folio(orig_folio, folio,
							      mapping,
							      index) == 0) {
						found = true;
					}
				} else if (nr > 1 &&
					   matched * 100 >=
						   nr * merge_threshold_pct) {
					pr_info("Partial match >= threshold (%u/%lu). Splitting large folio.\n",
						matched, nr);
					folio_lock(folio);
					if (!split_folio(folio)) {
						atomic_inc(&stat_folios_split);
						pr_info("Successfully split large folio.\n");
						/* We'll catch the sub-pages on the next scan iteration */
					} else {
						pr_debug(
							"Failed to split large folio.\n");
					}
					folio_unlock(folio);
				}
			} else if (folio_order(orig_folio) == 0 &&
				   folio_order(folio) == 0) {
				if (compare_folios(orig_folio, folio)) {
					pr_info("Exact duplicate verified!\n");
					pr_info("Match -> Inode 1: %lu (Index %lu) | Inode 2: %lu (Index %lu)\n",
						entry_mapping->host->i_ino,
						entry_index,
						mapping->host->i_ino, index);
					if (deduplicate_folio(orig_folio, folio,
							      mapping,
							      index) == 0) {
						found = true;
					}
				}
			}
			folio_put(orig_folio);
		} else {
			spin_lock(&folio_hash_lock);
			pr_debug(
				"Stale hash entry detected for Inode %lu. Removing.\n",
				entry_mapping->host->i_ino);
			hash_del(&entry->node);
			kfree(entry);
			spin_unlock(&folio_hash_lock);
		}

		spin_lock(&folio_hash_lock);
		if (found)
			break;
	}

	if (!found) {
		entry = kmalloc(sizeof(struct page_entry), GFP_ATOMIC);
		if (entry) {
			entry->hash = hash;
			entry->mapping = mapping;
			entry->index = index;
			hash_add(oob_folio_hash, &entry->node, hash);
		}
	}
	spin_unlock(&folio_hash_lock);
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

		if (!oob_scan.slot ||
		    list_is_head(&oob_scan.slot->list, &file_dedup_list)) {
			oob_scan.slot = list_first_entry(
				&file_dedup_list, struct file_dedup_slot, list);
			oob_scan.pgoff = 0;
			oob_scan.seqnr++;
		}

		slot = oob_scan.slot;
		struct inode *inode = slot->mapping->host;
		inode = igrab(inode); /* Safely attempt to grab the inode */

		if (!inode) { // Inode is being deleted
			spin_unlock(&file_dedup_lock);
			continue;
		}
		spin_unlock(&file_dedup_lock);

		folio = filemap_get_folio(slot->mapping, oob_scan.pgoff);
		if (!IS_ERR(folio)) {
			long nr = folio_nr_pages(folio);
			pgoff_t folio_start = folio_index(folio);

			check_and_store_folio(folio, slot->mapping,
					      oob_scan.pgoff);
			folio_put(folio);

			oob_scan.pgoff = folio_start + nr;
			pages_done += nr;
		} else {
			oob_scan.pgoff++;
			pages_done++;
		}

		atomic_add(pages_done, &stat_pages_scanned);

		unsigned long max_pages =
			(i_size_read(inode) + PAGE_SIZE - 1) >> PAGE_SHIFT;
		if (oob_scan.pgoff >= max_pages ||
		    oob_scan.pgoff >= MAX_PAGES_PER_FILE) {
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
		wait_event_interruptible_timeout(
			oob_dedup_wait, kthread_should_stop(),
			msecs_to_jiffies(sleep_millisecs));
	}
	clean_folio_hashtable();
	return 0;
}

/* sysfs attribute functions */
static ssize_t files_queued_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", atomic_read(&stat_files_queued));
}

static ssize_t pages_deduped_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", atomic_read(&stat_pages_deduped));
}

static ssize_t pages_scanned_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", atomic_read(&stat_pages_scanned));
}

static ssize_t folios_split_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", atomic_read(&stat_folios_split));
}

static ssize_t reset_stats_store(struct kobject *kobj,
				 struct kobj_attribute *attr, const char *buf,
				 size_t count)
{
	atomic_set(&stat_files_queued, 0);
	atomic_set(&stat_pages_deduped, 0);
	atomic_set(&stat_pages_scanned, 0);
	atomic_set(&stat_folios_split, 0);
	clean_folio_hashtable();
	pr_info("OOB_DEDUP: Stats and hash table reset via sysfs.\n");
	return count;
}

static ssize_t sleep_millisecs_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%u\n", sleep_millisecs);
}

static ssize_t sleep_millisecs_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	unsigned int val;
	if (kstrtouint(buf, 10, &val) == 0) {
		sleep_millisecs = val;
	}
	return count;
}

static struct kobj_attribute files_queued_attr = __ATTR_RO(files_queued);
static struct kobj_attribute pages_deduped_attr = __ATTR_RO(pages_deduped);
static struct kobj_attribute pages_scanned_attr = __ATTR_RO(pages_scanned);
static struct kobj_attribute folios_split_attr = __ATTR_RO(folios_split);
static struct kobj_attribute reset_stats_attr = __ATTR_WO(reset_stats);
static struct kobj_attribute sleep_millisecs_attr = __ATTR_RW(sleep_millisecs);

static struct attribute *oob_dedup_attrs[] = {
	&files_queued_attr.attr,
	&pages_deduped_attr.attr,
	&pages_scanned_attr.attr,
	&folios_split_attr.attr,
	&reset_stats_attr.attr,
	&sleep_millisecs_attr.attr,
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
					     sizeof(struct file_dedup_slot), 0,
					     SLAB_PANIC, NULL);
	if (!file_dedup_cache) {
		printk(KERN_EMERG "OOB_DEDUP: Cache creation failed!\n");
		return -ENOMEM;
	}

	oob_dedup_kobj = kobject_create_and_add("oob_dedup", kernel_kobj);
	if (!oob_dedup_kobj) {
		printk(KERN_EMERG
		       "OOB_DEDUP: Failed to create sysfs kobject\n");
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
		printk(KERN_EMERG
		       "OOB_DEDUP: kthread_run failed with err: %d\n",
		       err);
		goto out_remove_groups;
	}

	printk(KERN_INFO
	       "OOB_DEDUP: Initialization complete, thread running.\n");
	return 0;

out_remove_groups:
	sysfs_remove_groups(oob_dedup_kobj, oob_dedup_groups);
out_put_kobj:
	kobject_put(oob_dedup_kobj);
out_free_cache:
	kmem_cache_destroy(file_dedup_cache);
	return err;
}

void oob_dedup_wakeup(void)
{
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
			// ihold(mapping->host);
			pr_info("OOB_DEDUP: Queued file for dedup. Inode: %lu, Mapping: %p\n",
				mapping->host->i_ino, mapping);
			oob_dedup_wakeup();
		} else {
			err = -ENOMEM;
		}
	} else {
		pr_debug("OOB_DEDUP: Mapping %p already in queue, skipping.\n",
			 mapping);
	}
	spin_unlock(&file_dedup_lock);
	return err;
}

int oob_dedup_evict_inode(struct inode *inode)
{
	struct page_entry *entry;
	struct hlist_node *tmp;
	int bkt;
	bool found_in_hash = false;
	bool found_in_file_hash = false;
	struct file_dedup_slot *slot;
	struct address_space *mapping = inode->i_mapping;

	spin_lock(&file_dedup_lock);

	if (mapping) {
		slot = file_dedup_slot_lookup(file_dedup_hash,
					      inode->i_mapping);
		if (slot) {
			if (oob_scan.slot == slot) {
				struct file_dedup_slot *next =
					list_next_entry(slot, list);
				if (list_is_head(&next->list, &file_dedup_list))
					oob_scan.slot = NULL;
				else
					oob_scan.slot = next;
				oob_scan.pgoff = 0;
			}

			list_del(&slot->list);
			atomic_dec(&stat_files_queued);
			hash_del(&slot->hash);
			file_dedup_slot_free(file_dedup_cache, slot);
			found_in_file_hash = true;
		}
	}
	spin_unlock(&file_dedup_lock);

	spin_lock(&folio_hash_lock);
	hash_for_each_safe(oob_folio_hash, bkt, tmp, entry, node) {
		if (entry->mapping && entry->mapping->host == inode) {
			hash_del(&entry->node);
			kfree(entry);
			found_in_hash = true;
		}
	}
	spin_unlock(&folio_hash_lock);

	if (mapping) {
		struct folio *clones[16];
		int count;

		do {
			struct folio *f;
			// Start from index 0 on each batch to safely catch remaining clones
			XA_STATE(xas, &mapping->i_pages, 0);
			count = 0;

			xas_lock_irq(&xas);
			xas_for_each(&xas, f, ULONG_MAX) {
				if (xas_retry(&xas, f))
					continue;

				// If it's a clone (wrong mapping or index), queue it for execution
				if (f->mapping != mapping ||
				    f->index != xas.xa_index) {
					xas_store(&xas, NULL);
					mapping->nrpages--;
					clones[count++] = f;
					if (count == 16)
						break;
				}
			}
			xas_unlock_irq(&xas);

			for (int i = 0; i < count; i++) {
				folio_put(clones[i]);
			}

		} while (count > 0);
	}

	if (found_in_hash) {
		pr_info("OOB_DEDUP: Cleaned up entries corresponding to deleted Inode %lu from hash table.\n",
			inode->i_ino);
	}

	if (mapping) {
		struct folio *clones[16];
		int count;

		do {
			struct folio *f;
			/* Start from index 0 on each batch to safely catch remaining clones */
			XA_STATE(xas, &mapping->i_pages, 0);
			count = 0;

			xas_lock_irq(&xas);
			xas_for_each(&xas, f, ULONG_MAX) {
				if (xas_retry(&xas, f))
					continue;

				if (f->mapping != mapping ||
				    f->index != xas.xa_index) {
					xas_store(
						&xas,
						NULL); /* Wipe it from the tree */
					mapping->nrpages--; /* 🚨 CRUCIAL: Tell VFS the page is gone! */

					clones[count++] = f;
					if (count == 16)
						break; /* Stop if our safe batch array is full */
				}
			}
			xas_unlock_irq(&xas);

			/* Safely drop all references outside the spinlock */
			for (int i = 0; i < count; i++) {
				folio_put(clones[i]);
			}

		} while (count >
			 0); /* Repeat until the tree is perfectly clean */
	}

	if (found_in_hash) {
		pr_info("OOB_DEDUP: Cleaned up entries corresponding to deleted Inode %lu from hash table.\n",
			inode->i_ino);
	}

	// if (found_in_file_hash) {
	//   iput(inode);
	//}

	if (found_in_hash) {
		pr_info("OOB_DEDUP: Cleaned up entries corresponding to deleted Inode %lu from hash table.\n",
			inode->i_ino);
	}
	return 0;
}

EXPORT_SYMBOL_GPL(oob_dedup_add_file);
// EXPORT_SYMBOL_GPL(oob_dedup_remove_file);
EXPORT_SYMBOL_GPL(oob_dedup_evict_inode);

subsys_initcall(oob_dedup_init);
