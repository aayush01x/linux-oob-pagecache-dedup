/* struct oob_scan - cursor for scanning */
struct oob_scan {
    struct file_dedup_slot *slot;
    unsigned long pgoff;   
    unsigned long seqnr;
};

/*
* store mapping and index instead of raw PFN
* to check if some page still exists in cache or is evicted.
*/
struct page_entry {
    u32 hash;
    struct address_space *mapping;
    pgoff_t index;
    unsigned int anchor_idx;    /* which anchor position (0..N-1) */
    struct hlist_node node;
};

/*
 * structures to maintain a symmetric deduped folio
 * so that all other operations become easier 
 */
struct oob_dedup_info {
    spinlock_t lock;
    struct list_head rmap_list;
    unsigned int rmap_count;
    struct hlist_node node;
}__attribute__((aligned(8)));

struct oob_dedup_rmap_entry {
    struct address_space* mapping;
    pgoff_t index;
    struct list_head list;
};


// function to check if the folio has been deduplicated
static inline bool folio_test_dedup(struct folio *folio)
{
    return ((unsigned long)folio->mapping & PAGE_MAPPING_FLAGS) == PAGE_MAPPING_DEDUP;
}

// function to clean the bits on the mapping pointer and cast it to a oob_dedup_info struct
static inline struct oob_dedup_info *folio_dedup_info(struct folio *folio)
{
    if (!folio_test_dedup(folio))
        return NULL;
    return (struct oob_dedup_info *)((unsigned long)folio->mapping & ~PAGE_MAPPING_FLAGS);
}

// set a newly created oob_dedup_info pointer to a folio->mapping pointer after setting the special bit 
static inline void folio_set_dedup_info(struct folio *folio, struct oob_dedup_info *info)
{
    folio->mapping = (struct address_space *)((unsigned long)info | PAGE_MAPPING_DEDUP);
}

static inline bool folio_shares_mapping(struct folio *folio, struct address_space *mapping)
{
	if (likely(!folio_test_dedup(folio)))
		return folio->mapping == mapping;

	if (folio_mapping(folio) == mapping)
		return true;

	struct oob_dedup_info *info = folio_dedup_info(folio);
	struct oob_dedup_rmap_entry *entry;
	bool found = false;

	spin_lock(&info->lock);
	list_for_each_entry(entry, &info->rmap_list, list) {
		if (entry->mapping == mapping) {
			found = true;
			break;
		}
	}
	spin_unlock(&info->lock);
	return found;
}

static inline bool folio_shares_index(struct folio *folio, struct address_space *mapping, pgoff_t index)
{
	if (likely(!folio_test_dedup(folio)))
		return folio->index == index;

	struct oob_dedup_info *info = folio_dedup_info(folio);
	struct oob_dedup_rmap_entry *entry;
	bool found = false;

	spin_lock(&info->lock);
	list_for_each_entry(entry, &info->rmap_list, list) {
		if (entry->mapping == mapping && entry->index == index) {
			found = true;
			break;
		}
	}
	spin_unlock(&info->lock);
	return found;
}

static inline pgoff_t folio_index_in(struct folio *folio, struct address_space *mapping)
{
	if (likely(!folio_test_dedup(folio)))
		return folio->index;

	struct oob_dedup_info *info = folio_dedup_info(folio);
	struct oob_dedup_rmap_entry *entry;
	pgoff_t index = folio->index;

	spin_lock(&info->lock);
	list_for_each_entry(entry, &info->rmap_list, list) {
		if (entry->mapping == mapping) {
			index = entry->index;
			break;
		}
	}
	spin_unlock(&info->lock);
	return index;
}

static inline loff_t folio_pos_in(struct folio *folio, struct address_space *mapping)
{
	return (loff_t)folio_index_in(folio, mapping) << PAGE_SHIFT;
}

void oob_dedup_disconnect_folio(struct folio *folio, struct address_space *mapping, pgoff_t index);
int oob_folio_break_dedup(struct address_space *mapping, struct folio **foliop, 
                          loff_t pos, size_t len);

static inline loff_t folio_pos_near(struct folio *folio, 
                                    struct address_space *mapping, 
                                    pgoff_t target_index)
{
    if (likely(!folio_test_dedup(folio)))
        return folio_pos(folio);

    struct oob_dedup_info *info = folio_dedup_info(folio);
    struct oob_dedup_rmap_entry *entry;
    pgoff_t found_index = folio->index;

    spin_lock(&info->lock);
    list_for_each_entry(entry, &info->rmap_list, list) {
        /* For intra-file, find the entry that contains the index we are currently truncating */
        if (entry->mapping == mapping && 
            target_index >= entry->index && 
            target_index < entry->index + folio_nr_pages(folio)) {
            found_index = entry->index;
            break;
        }
    }
    spin_unlock(&info->lock);
    return (loff_t)found_index << PAGE_SHIFT;
}

/* Index-aware page cache removal for intra-file dedup (defined in filemap.c) */
extern void filemap_remove_folio_at(struct folio *folio,
				    struct address_space *mapping,
				    pgoff_t index);

