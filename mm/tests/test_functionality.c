#include <kunit/test.h>

static void test_folio_set_dedup_info(struct kunit *test)
{
    struct folio *dummy_folio = kzalloc(sizeof(struct folio), GFP_KERNEL);
    struct oob_dedup_info *info = kzalloc(sizeof(struct oob_dedup_info), GFP_KERNEL);

    KUNIT_ASSERT_NOT_NULL(test, dummy_folio);
    KUNIT_ASSERT_NOT_NULL(test, info);

    // Perform the hijack
    folio_set_dedup_info(dummy_folio, info);

    // Verify
    KUNIT_EXPECT_TRUE(test, folio_test_dedup(dummy_folio));
    KUNIT_EXPECT_PTR_EQ(test, folio_dedup_info(dummy_folio), info);

    kfree(info);
    kfree(dummy_folio);
}

static void test_dedup_rollback_logic(struct kunit *test)
{
    struct folio *orig_folio = kzalloc(sizeof(*orig_folio), GFP_KERNEL);
    struct oob_dedup_info *info = kzalloc(sizeof(*info), GFP_KERNEL);
    struct oob_dedup_rmap_entry *orig_entry = kzalloc(sizeof(*orig_entry), GFP_KERNEL);
    struct address_space dummy_mapping; 
    pgoff_t dummy_index = 42;

    KUNIT_ASSERT_NOT_NULL(test, orig_folio);
    KUNIT_ASSERT_NOT_NULL(test, info);
    KUNIT_ASSERT_NOT_NULL(test, orig_entry);

    /* Setup initial deduplicated state */
    spin_lock_init(&info->lock);
    INIT_LIST_HEAD(&info->rmap_list);
    orig_entry->mapping = &dummy_mapping;
    orig_entry->index = dummy_index;
    list_add(&orig_entry->list, &info->rmap_list);
    info->rmap_count = 1;

    folio_set_dedup_info(orig_folio, info);

    /* Simulate the Rollback (if xas_store failed) */
    bool dissolve_needed;
    spin_lock(&info->lock);
    dissolve_needed = (info->rmap_count == 1);
    spin_unlock(&info->lock);

    if (dissolve_needed) {
        orig_folio->mapping = orig_entry->mapping;
        orig_folio->index = orig_entry->index;
        kfree(orig_entry);
        kfree(info);
    }

    /* Verify it reverted successfully */
    KUNIT_EXPECT_FALSE(test, folio_test_dedup(orig_folio));
    KUNIT_EXPECT_PTR_EQ(test, orig_folio->mapping, &dummy_mapping);
    KUNIT_EXPECT_EQ(test, orig_folio->index, dummy_index);

    kfree(orig_folio);
}

static struct kunit_case oob_dedup_test_cases[] = {
    KUNIT_CASE(test_folio_set_dedup_info),
    KUNIT_CASE(test_dedup_rollback_logic),
    {}
};

static struct kunit_suite oob_dedup_test_suite = {
    .name = "oob_dedup_struct_tests",
    .test_cases = oob_dedup_test_cases,
};

kunit_test_suite(oob_dedup_test_suite);
