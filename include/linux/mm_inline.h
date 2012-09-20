#ifndef LINUX_MM_INLINE_H
#define LINUX_MM_INLINE_H

#include <linux/huge_mm.h>

/**
 * page_is_file_cache - should the page be on a file LRU or anon LRU?
 * @page: the page to test
 *
 * Returns 1 if @page is page cache page backed by a regular filesystem,
 * or 0 if @page is anonymous, tmpfs or otherwise ram or swap backed.
 * Used by functions that manipulate the LRU lists, to sort a page
 * onto the right LRU list.
 *
 * We would like to get this info without a page flag, but the state
 * needs to survive until the page is last deleted from the LRU, which
 * could be as far down as __page_cache_release.
 */
static inline int page_is_file_cache(struct page *page)
{
	return !PageSwapBacked(page);
}

static inline void
__add_page_to_lru_list(struct gang *gang, struct page *page, enum lru_list l,
		       struct list_head *head)
{
	int numpages = hpage_nr_pages(page);

	list_add(&page->lru, head);
	gang->lru[l].nr_pages += numpages;
	__mod_zone_page_state(gang_zone(gang), NR_LRU_BASE + l, numpages);
	mem_cgroup_add_lru_list(page, l);
}

static inline void
add_page_to_lru_list(struct gang *gang, struct page *page, enum lru_list l)
{
	__add_page_to_lru_list(gang, page, l, &gang->lru[l].list);
}

static inline void
del_page_from_lru_list(struct gang *gang, struct page *page, enum lru_list l)
{
	int numpages = hpage_nr_pages(page);

	list_del(&page->lru);
	gang->lru[l].nr_pages -= numpages;
	__mod_zone_page_state(gang_zone(gang), NR_LRU_BASE + l, -numpages);
	mem_cgroup_del_lru_list(page, l);
}

/**
 * page_lru_base_type - which LRU list type should a page be on?
 * @page: the page to test
 *
 * Used for LRU list index arithmetic.
 *
 * Returns the base LRU type - file or anon - @page should be on.
 */
static inline enum lru_list page_lru_base_type(struct page *page)
{
	if (page_is_file_cache(page))
		return LRU_INACTIVE_FILE;
	return LRU_INACTIVE_ANON;
}

static inline void
del_page_from_lru(struct gang *gang, struct page *page)
{
	enum lru_list l;
	int numpages = hpage_nr_pages(page);

	list_del(&page->lru);
	if (PageUnevictable(page)) {
		__ClearPageUnevictable(page);
		l = LRU_UNEVICTABLE;
	} else {
		l = page_lru_base_type(page);
		if (PageActive(page)) {
			__ClearPageActive(page);
			l += LRU_ACTIVE;
		}
	}
	gang->lru[l].nr_pages -= numpages;
	__mod_zone_page_state(gang_zone(gang), NR_LRU_BASE + l, -numpages);
	mem_cgroup_del_lru_list(page, l);
}

/**
 * page_lru - which LRU list should a page be on?
 * @page: the page to test
 *
 * Returns the LRU list a page should be on, as an index
 * into the array of LRU lists.
 */
static inline enum lru_list page_lru(struct page *page)
{
	enum lru_list lru;

	if (PageUnevictable(page))
		lru = LRU_UNEVICTABLE;
	else {
		lru = page_lru_base_type(page);
		if (PageActive(page))
			lru += LRU_ACTIVE;
	}

	return lru;
}

#endif
