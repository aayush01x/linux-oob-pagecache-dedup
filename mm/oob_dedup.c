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

/* Global Queue */
static LIST_HEAD(file_dedup_list);

static DEFINE_HASHTABLE(file_dedup_hash, 10);

static struct kmem_cache *file_dedup_cache;

static DEFINE_SPINLOCK(file_dedup_lock);

static struct task_struct *oob_dedup_thread;
static DECLARE_WAIT_QUEUE_HEAD(oob_dedup_wait);

static unsigned long pages_scanned;
static unsigned int sleep_millisecs = 20;
static unsigned int pages_to_scan = 100;

#define MAX_PAGES_PER_FILE 1024

/*
* struct oob_scan - cursor for scanning
*/
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

static void oob_dedup_do_scan(void)
{
    struct file_dedup_slot *slot;
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
	return 0;
}

static int __init oob_dedup_init(void)
{
	printk(KERN_EMERG "oob_dedup: Entering init function...\n");
	int err;
	hash_init(file_dedup_hash);

	file_dedup_cache = kmem_cache_create("file_dedup_slot",
					sizeof(struct file_dedup_slot),
					0, SLAB_PANIC, NULL);
	if (!file_dedup_cache){
		printk(KERN_EMERG "oob_dedup: Cache creation failed!\n");
		return -ENOMEM;
	}

	oob_dedup_thread = kthread_run(oob_dedup_thread_fn, NULL, "oob_dedupd");
	if (IS_ERR(oob_dedup_thread)) {
		// pr_err("oob_dedup: Creating kthread failed\n");
		err = PTR_ERR(oob_dedup_thread);
		printk(KERN_EMERG "OOB_DEDUP: kthread_run failed with err: %d\n", err);
		goto out_free_cache;
	}

	// pr_info("oob_dedup: Initialized kthread\n");
	printk(KERN_EMERG "OOB_DEDUP: Initialization complete, thread running.\n");
	return 0;

out_free_cache:
	kmem_cache_destroy(file_dedup_cache);
	return err;
}

void oob_dedup_wakeup(void) {
    if (waitqueue_active(&oob_dedup_wait))
        wake_up_interruptible(&oob_dedup_wait);
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