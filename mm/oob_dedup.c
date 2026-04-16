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
#include "oob_dedup.h"

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
static unsigned int pages_to_scan = 100;
#define MAX_PAGES_PER_FILE 1024

/* sysfs kobject and counters for the sysfs layer */
static struct kobject *oob_dedup_kobj;

static atomic_t stat_files_queued = ATOMIC_INIT(0);
static atomic_t stat_pages_deduped = ATOMIC_INIT(0);
static atomic_t stat_pages_scanned = ATOMIC_INIT(0);



static struct oob_scan oob_scan = {
    .slot = NULL,
    .pgoff = 0,
    .seqnr = 0,
};

static DEFINE_HASHTABLE(oob_folio_hash, 12);





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
    XA_STATE(xas, &mapping->i_pages, index);
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

    // aquire locks for the folios
    if (orig_folio < dup_folio) {
        folio_lock(orig_folio);
        folio_lock(dup_folio);
    } else {
        folio_lock(dup_folio);
        folio_lock(orig_folio);
    }
    
    /*
     * MUahahaha
     * checks to only have very clean folios deduplicated
     * no folios in write backs 
     * no folios in reads 
     * and no dirty folios 
     * */
    if (!folio_test_uptodate(orig_folio) || !folio_test_uptodate(dup_folio) ||
        folio_test_dirty(orig_folio) || folio_test_dirty(dup_folio) ||
        folio_test_writeback(orig_folio) || folio_test_writeback(dup_folio) ||
        folio_mapped(orig_folio) || folio_mapped(dup_folio)) {
        err = -EBUSY;
        goto out_unlock;
    }

    // a check to make sure that the dup_folio was not changed before deduplication 
    if (folio_mapping(dup_folio) != mapping || folio_index(dup_folio) != index ||
        !folio_mapping(orig_folio)) {
        err = -EAGAIN;
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
    folio_get(orig_folio);
    xas_lock_irq(&xas);
    xas_store(&xas, orig_folio);
    if (xas_error(&xas)) {
        // xas_store failed
        xas_unlock_irq(&xas);
        folio_put(orig_folio);
        
        spin_lock(&info->lock);
        list_del(&dup_entry->list);
        info->rmap_count--;
        
        
        //if the orig_folio wasn't deduplicated before
        // need to return mapping to normal and free info and other struct
        bool dissolve_needed = (info->rmap_count == 1);
        spin_unlock(&info->lock);
        
        if (dissolve_needed){
			orig_folio->mapping = orig_entry->mapping;
			orig_folio->index = orig_entry->index;
			
			kmem_cache_free(rmap_entry_cache, orig_entry);
			kmem_cache_free(dedup_info_cache, info);
		}
        
        err = xas_error(&xas);
        goto out_unlock;
    }
    xas_unlock_irq(&xas);

    // orphan the dup_folio
    dup_folio->mapping = NULL;
    dup_folio->index = 0;

    folio_unlock(dup_folio);
    folio_unlock(orig_folio);
    folio_put(dup_folio);

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

        struct folio *orig_folio = filemap_get_folio(entry_mapping, entry_index);

        if (!IS_ERR(orig_folio)) {
            if (orig_folio == folio) {
                pr_debug("Folios already share physical memory. Skipping.\n");
                folio_put(orig_folio);
                spin_lock(&folio_hash_lock);
                found = true;
                break;
            }

            if (compare_folios(orig_folio, folio)) {
                pr_info("Exact duplicate verified!\n");
                pr_info("Match -> Inode 1: %lu (Index %lu) | Inode 2: %lu (Index %lu)\n",
                         entry_mapping->host->i_ino, entry_index,
                         mapping->host->i_ino, index);
                if (deduplicate_folio(orig_folio, folio, mapping, index) == 0) {
                    found = true;
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

        if (!oob_scan.slot || list_is_head(&oob_scan.slot->list, &file_dedup_list)) {
            oob_scan.slot = list_first_entry(&file_dedup_list, struct file_dedup_slot, list);
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
			check_and_store_folio(folio, slot->mapping, oob_scan.pgoff);
            folio_put(folio);
		}

        pages_done++;
        atomic_inc(&stat_pages_scanned);
        oob_scan.pgoff++;

		unsigned long max_pages = (i_size_read(inode) + PAGE_SIZE - 1) >> PAGE_SHIFT;
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

/* 
 * in case the kernel decides that the folio is not need in the page cache
 * the folio is removed from the page cahce 
 * hence we handle it here
 * see page_cache_delete in mm/filemap.c for more info 
 *
 * */
void oob_dedup_disconnect_folio(struct folio *folio, struct address_space *mapping)
{
  struct oob_dedup_info *info = folio_dedup_info(folio);
  struct oob_dedup_rmap_entry *entry, *tmp;
  bool dissolve = false;
	unsigned long flags;

    // since the ancestor? function holds irqsave(non interruptible lock) we need to keep using irqsave locks
    spin_lock_irqsave(&info->lock, flags);
    list_for_each_entry_safe(entry, tmp, &info->rmap_list, list) {
        if (entry->mapping == mapping) {
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
        folio->mapping = last->mapping;
        folio->index = last->index;
        list_del(&last->list);
        kmem_cache_free(rmap_entry_cache, last);
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

static struct kobj_attribute files_queued_attr = __ATTR_RO(files_queued);
static struct kobj_attribute pages_deduped_attr = __ATTR_RO(pages_deduped);
static struct kobj_attribute pages_scanned_attr = __ATTR_RO(pages_scanned);
static struct kobj_attribute sleep_millisecs_attr = __ATTR_RW(sleep_millisecs);

static struct attribute *oob_dedup_attrs[] = {
    &files_queued_attr.attr,
    &pages_deduped_attr.attr,
    &pages_scanned_attr.attr,
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
        // ihold(mapping->host);
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
// int oob_dedup_evict_inode(struct inode *inode)
// {
// 	pr_debug("OOB_DEDUP: ENTERING EVICT NODE FUCTION\n");
// 	dump_stack();
//     struct page_entry *entry;
//     struct hlist_node *tmp;
//     int bkt;
//     bool found_in_hash = false;
//     bool found_in_file_hash = false;
//     struct file_dedup_slot *slot;
//     struct address_space *mapping = inode->i_mapping;
//     struct folio* folio;
//     XA_STATE(xas, &mapping->i_pages, 0);
//
//     spin_lock(&file_dedup_lock);
//
//     if (mapping) {
//         slot = file_dedup_slot_lookup(file_dedup_hash, inode->i_mapping);
//         if (slot) {
//             if (oob_scan.slot == slot) {
//                 struct file_dedup_slot *next = list_next_entry(slot, list);
//                 if (list_is_head(&next->list, &file_dedup_list))
//                     oob_scan.slot = NULL;
//                 else
//                     oob_scan.slot = next;
//                 oob_scan.pgoff = 0;
//             }
//
//             list_del(&slot->list);
//             atomic_dec(&stat_files_queued);
//             hash_del(&slot->hash);
//             file_dedup_slot_free(file_dedup_cache, slot);
//             found_in_file_hash = true;
//         }
//     }
//     spin_unlock(&file_dedup_lock);
//
//     spin_lock(&folio_hash_lock);
//     hash_for_each_safe(oob_folio_hash, bkt, tmp, entry, node) {
//         if (entry->mapping && entry->mapping->host == inode) {
//             hash_del(&entry->node);
//             kfree(entry);
//             found_in_hash = true;
//         }
//     }
//     spin_unlock(&folio_hash_lock);
//
//     if (!mapping) return 0;
//
//     /* clean up deduped folios and handle dissolution */
//     xas_lock_irq(&xas);
//     xas_for_each(&xas, folio, ULONG_MAX) {
//         if (xas_retry(&xas, folio)) continue;
//         if (!folio_test_dedup(folio)) continue;
//
//         // lock the folio first to safely change its identity lest we might result in deadlock
//         if (!folio_trylock(folio)) {
//             continue; 
//         }
//
//         struct oob_dedup_info *info = folio_dedup_info(folio);
//         struct oob_dedup_rmap_entry *entry, *tmp_entry;
//         bool dissolve = false;
//
//         spin_lock(&info->lock);
//         list_for_each_entry_safe(entry, tmp_entry, &info->rmap_list, list) {
//             if (entry->mapping == mapping) {
//                 list_del(&entry->list);
//                 info->rmap_count--;
//                 kmem_cache_free(rmap_entry_cache, entry);
//             }
//         }
//
//         // if after removal of the peer we are left with only one entry
//         // we just reinstantiate it as a proper folio 
//         if (info->rmap_count == 1) {
//             struct oob_dedup_rmap_entry *last = list_first_entry(&info->rmap_list, 
//                                                struct oob_dedup_rmap_entry, list);
//
//             folio->mapping = last->mapping;
//             folio->index = last->index;
//
//             list_del(&last->list);
//             kmem_cache_free(rmap_entry_cache, last);
//             dissolve = true; 
//         }
//
//         spin_unlock(&info->lock);
//
//         if (dissolve) {
//             kmem_cache_free(dedup_info_cache, info);
//         }
//
//         folio_unlock(folio);
//     }
//     xas_unlock_irq(&xas);
//
//     // if (found_in_file_hash) {
//     //   iput(inode);
//     //}
//
//     // if (found_in_hash) {
//     //     pr_info("OOB_DEDUP: Cleaned up entries corresponding to deleted Inode %lu from hash table.\n", inode->i_ino);
//     // }
//     return 0;
// }

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
                oob_scan.pgoff = 0;
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


EXPORT_SYMBOL_GPL(oob_dedup_add_file);
// EXPORT_SYMBOL_GPL(oob_dedup_remove_file);
EXPORT_SYMBOL_GPL(oob_dedup_evict_inode);

subsys_initcall(oob_dedup_init);

#ifdef CONFIG_KUNIT
#include "tests/test_functionality.c"
#endif
