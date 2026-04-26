#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/pid.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/rcupdate.h>
#include <linux/xarray.h>
#include <linux/highmem.h>
#include <linux/crc32.h>
#include <linux/hashtable.h>

#define MODULE_NAME "custom_thread"
#define BIT_TO_CHECK 9


struct my_monitor_data {
    int run;                // 0 = Paused, 1 = Running
    int pid_curr;
    char string_b[64];
    
    struct mutex data_lock; 
    wait_queue_head_t wq;   // <--- The Waiting Room
};

DEFINE_HASHTABLE(page_hash_table, 10);
static struct my_monitor_data *ctx;
static struct task_struct *monitor_task;
static struct kobject *my_kobj;



struct page_entry {
    u32 hash;
    unsigned long pfn;
    struct hlist_node node;
};

static u32 hash_page_content(struct page *page)
{
    void *addr;
    u32 hash;
    // gives a virtual address for a page struct /folio struct
    addr = kmap_local_page(page);
    
    hash = crc32_le(~0, addr, PAGE_SIZE);
    
    kunmap_local(addr);
    return hash;
}

static void check_and_store_hash(struct page *page, pgoff_t index)
{   
    struct page_entry *entry;
    u32 hash;
    bool found = false;
    unsigned long pfn = page_to_pfn(page);

    hash = hash_page_content(page);

    hash_for_each_possible(page_hash_table, entry, node, hash) {
        if (entry->hash == hash) {
            if (entry->pfn != pfn) {
                pr_alert("[%s] DUPLICATE CONTENT FOUND!\n", MODULE_NAME);
                pr_alert("    Hash: %08x | Original PFN: %lu | New PFN: %lu (Index %lu)\n", 
                         hash, entry->pfn, pfn, index);
                found = true;
            }
        }
    }

    if (!found) {
        entry = kmalloc(sizeof(struct page_entry), GFP_KERNEL);
        if (entry) {
            entry->hash = hash;
            entry->pfn = pfn;
            // static int debug_count = 0;
            // if (debug_count < 5) {
            //     pr_info("[%s] Hashed PFN %lu (Index %lu) -> %08x\n", 
            //             MODULE_NAME, pfn, index, hash);
            //     debug_count++;
            // }
            hash_add(page_hash_table, &entry->node, hash);
        }
    }
}

static void scan_address_space(struct address_space *mapping)
{
    XA_STATE(xas, &mapping->i_pages, 0);
    struct page *page;
    struct folio *folio;
    size_t i, nr_pages;

    rcu_read_lock();
    
    xas_for_each(&xas, page, ULONG_MAX) {
        if (xas_retry(&xas, page))
            continue;
        
        // Pin the page (works for compound pages/folios too)
        if (!get_page_unless_zero(page))
            continue;

        // Convert to folio (Standard in Linux 6.6)
        folio = page_folio(page);
        nr_pages = folio_nr_pages(folio);

        // Temporarily unlock RCU to process
        rcu_read_unlock();

        // --- ITERATE SUBPAGES ---
        for (i = 0; i < nr_pages; i++) {
            struct page *subpage = folio_page(folio, i);
            
            // Calculate the correct index for this subpage
            pgoff_t current_index = xas.xa_index + i;

            // Check this specific 4KB subpage
            check_and_store_hash(subpage, current_index);
            
            // Yield every 32 pages to be polite
            if (i % 32 == 0) cond_resched();
        }

        put_page(page);
        rcu_read_lock(); // Re-acquire for next iteration
    }
    
    rcu_read_unlock();
}

static void clean_hashtable(void)
{
    struct page_entry *entry;
    struct hlist_node *tmp;
    int bkt;

    hash_for_each_safe(page_hash_table, bkt, tmp, entry, node) {
        hash_del(&entry->node);
        kfree(entry);
    }
}

static void perform_scan(pid_t pid)
{
    struct task_struct *task;
    struct files_struct *files;
    struct file *file;
    int fd = 0;

    pr_info("[%s] Starting content scan for PID: %d\n", MODULE_NAME, pid);

    clean_hashtable();

    // Get task
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        pr_info("Could not find PID: %d\n",pid);
        return;
    }
    get_task_struct(task);
    rcu_read_unlock();

    files = task->files;
    if (files) {
        spin_lock(&files->file_lock);
        
        // Iterate FDs
        for (fd = 0; fd < files_fdtable(files)->max_fds; fd++) {
            // <--- FIXED: fcheck_files replaced with files_lookup_fd_rcu
            file = files_lookup_fd_rcu(files, fd);
            
            if (!file) continue;

            if (file->f_mapping) {
                unsigned long flags = file->f_mapping->flags;
                pr_info("[%s] Found flags : %lx for fd = %d\n", MODULE_NAME, flags,fd);
                
                if (test_bit(BIT_TO_CHECK, &flags)) {
                     // Grab reference to process outside lock
                     get_file(file);
                     spin_unlock(&files->file_lock);
					 pr_info("[%s] scanning address_space for fd = %d", MODULE_NAME, fd);
                     scan_address_space(file->f_mapping);

                     fput(file);
                     spin_lock(&files->file_lock);
                }
            }
        }
        spin_unlock(&files->file_lock);
    }
    
    put_task_struct(task);
    clean_hashtable();
    
    pr_info("[%s] Content scan complete.\n", MODULE_NAME);
}
/*
 * ===============================================================
 * Sysfs: The "Run" Switch
 * ===============================================================
 */
static ssize_t run_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", ctx->run);
}

static ssize_t run_store(struct kobject *kobj, struct kobj_attribute *attr,
                         const char *buf, size_t count)
{
    int ret, val;
    ret = kstrtoint(buf, 10, &val);
    if (ret < 0) return ret;

    mutex_lock(&ctx->data_lock);
    ctx->run = val;
    mutex_unlock(&ctx->data_lock);

    /* * CRITICAL STEP:
     * If user wrote '1', we must wake up the sleeping thread!
     */
    if (val == 1) {
        wake_up_interruptible(&ctx->wq);
    }
    
    return count;
}

static struct kobj_attribute run_attr = __ATTR(run, 0664, run_show, run_store);

/*
 * ===============================================================
 * Sysfs: Other Attributes
 * ===============================================================
 */
// (Same as before, simplified for brevity)
static ssize_t pid_curr_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", ctx->pid_curr);
}
static ssize_t pid_curr_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    int val,ret; 
    ret = kstrtoint(buf, 10, &val);
    if(ret<0) return ret;
    ctx->pid_curr = val;
    return count;
}

static struct kobj_attribute pid_curr_attr = __ATTR(pid_curr, 0664, pid_curr_show, pid_curr_store);

static ssize_t string_b_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    ssize_t ret;
    mutex_lock(&ctx->data_lock);
    ret = sprintf(buf, "%s\n", ctx->string_b);
    mutex_unlock(&ctx->data_lock);
    return ret;
}

static ssize_t string_b_store(struct kobject *kobj, struct kobj_attribute *attr,
                              const char *buf, size_t count)
{
    mutex_lock(&ctx->data_lock);
    // Safe string copy ensuring null termination
    strscpy(ctx->string_b, buf, sizeof(ctx->string_b));
    // Remove newline if present
    if (count > 0 && ctx->string_b[count-1] == '\n')
        ctx->string_b[count-1] = '\0';
    mutex_unlock(&ctx->data_lock);
    return count;
}

static struct kobj_attribute string_b_attr = __ATTR(string_b, 0664, string_b_show, string_b_store);

static struct attribute *my_attrs[] = {
    &run_attr.attr,         // <--- Added
    &pid_curr_attr.attr,
    &string_b_attr.attr,
    NULL,
};

static struct attribute_group my_attr_group = { .attrs = my_attrs };

/*
 * ===============================================================
 * The Thread Function
 * ===============================================================
 */
static int thread_fn(void *data)
{
    struct my_monitor_data *local_ctx = (struct my_monitor_data *)data;
    
    pr_info("[%s] Thread started. Waiting for run=1...\n", MODULE_NAME);

    while (!kthread_should_stop()) {
        
        /* * 1. WAIT HERE
         * This puts the thread to SLEEP until:
         * A) condition becomes true (ctx->run == 1)
         * B) kthread_stop is called
         */
        wait_event_interruptible(local_ctx->wq, 
                                 (local_ctx->run == 1) || kthread_should_stop());

        // Check if we woke up because we need to die
        if (kthread_should_stop())
            break;

        // 2. Do the work (only if run is 1)
        if (local_ctx->run == 1 && local_ctx->pid_curr != 0) {
            

            pr_info("[%s] Working... A: %d\n", MODULE_NAME, local_ctx->pid_curr);
            perform_scan(local_ctx->pid_curr);

            // Sleep 10s between prints
            // Note: If you set run=0 during this sleep, it will finish the sleep
            // and then pause at the TOP of the loop next time.
            msleep(10000); 
        }
    }

    pr_info("[%s] Thread stopping.\n", MODULE_NAME);
    return 0;
}

/*
 * ===============================================================
 * Init & Exit
 * ===============================================================
 */
static int __init monitor_init(void)
{
    int ret;
    
    ctx = kzalloc(sizeof(struct my_monitor_data), GFP_KERNEL);
    if (!ctx) return -ENOMEM;

    mutex_init(&ctx->data_lock);
    init_waitqueue_head(&ctx->wq); // <--- Initialize the Wait Queue
    ctx->run = 0;                  // Start paused
    ctx->pid_curr = 0;

    my_kobj = kobject_create_and_add("controlled_thread", kernel_kobj);
    if (!my_kobj) { kfree(ctx); return -ENOMEM; }

    ret = sysfs_create_group(my_kobj, &my_attr_group);
    if (ret) { kobject_put(my_kobj); kfree(ctx); return ret; }

    monitor_task = kthread_run(thread_fn, ctx, "my_worker");
    if (IS_ERR(monitor_task)) return PTR_ERR(monitor_task);

    return 0;
}

static void __exit monitor_exit(void)
{
    if (monitor_task) kthread_stop(monitor_task);
    sysfs_remove_group(my_kobj, &my_attr_group);
    kobject_put(my_kobj);
    kfree(ctx);
}

module_init(monitor_init);
module_exit(monitor_exit);
MODULE_LICENSE("GPL");
