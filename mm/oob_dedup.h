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

void oob_dedup_disconnect_folio(struct folio *folio, struct address_space *mapping);
