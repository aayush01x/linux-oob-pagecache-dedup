#ifndef _LINUX_FILE_DEDUP_SLOT_H
#define _LINUX_FILE_DEDUP_SLOT_H

#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/slab.h>

struct address_space;
/*
 * struct file_dedup_slot - entry for a file queued for out-of-band dedup
 * @hash: link to the global lookup hash table
 * @list: link into the global scanner work queue
 * @mapping: the address_space (page cache) of the file
 */
struct file_dedup_slot {
	struct hlist_node hash;
	struct list_head list;
	struct address_space *mapping;
};

#define file_dedup_slot_entry(ptr, type, member) \
	container_of(ptr, type, member)

static inline struct file_dedup_slot *file_dedup_slot_alloc(struct kmem_cache *cache)
{
	if (!cache)
		return NULL;
	return kmem_cache_zalloc(cache, GFP_KERNEL);
}

static inline void file_dedup_slot_free(struct kmem_cache *cache, struct file_dedup_slot *slot)
{
	kmem_cache_free(cache, slot);
}

#define file_dedup_slot_lookup(_hashtable, _mapping)			       \
({									       \
	struct file_dedup_slot *tmp_slot, *res_slot = NULL;		       \
									       \
	hash_for_each_possible(_hashtable, tmp_slot, hash, (unsigned long)_mapping) \
		if (_mapping == tmp_slot->mapping) {			       \
			res_slot = tmp_slot;				       \
			break;						       \
		}							       \
									       \
	res_slot;							       \
})

#define file_dedup_slot_insert(_hashtable, _mapping, _slot)		       \
({									       \
	(_slot)->mapping = _mapping;					       \
	hash_add(_hashtable, &(_slot)->hash, (unsigned long)_mapping);	       \
})

#endif /* _LINUX_FILE_DEDUP_SLOT_H */