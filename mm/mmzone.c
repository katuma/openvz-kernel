/*
 * linux/mm/mmzone.c
 *
 * management codes for pgdats and zones.
 */


#include <linux/stddef.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/mmgang.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/module.h>
#include <linux/mm_inline.h>
#include <linux/migrate.h>

#include "internal.h"

struct pglist_data *first_online_pgdat(void)
{
	return NODE_DATA(first_online_node);
}
EXPORT_SYMBOL(first_online_pgdat);

struct pglist_data *next_online_pgdat(struct pglist_data *pgdat)
{
	int nid = next_online_node(pgdat->node_id);

	if (nid == MAX_NUMNODES)
		return NULL;
	return NODE_DATA(nid);
}
EXPORT_SYMBOL(next_online_pgdat);

/*
 * next_zone - helper magic for for_each_zone()
 */
struct zone *next_zone(struct zone *zone)
{
	pg_data_t *pgdat = zone->zone_pgdat;

	if (zone < pgdat->node_zones + MAX_NR_ZONES - 1)
		zone++;
	else {
		pgdat = next_online_pgdat(pgdat);
		if (pgdat)
			zone = pgdat->node_zones;
		else
			zone = NULL;
	}
	return zone;
}

static inline int zref_in_nodemask(struct zoneref *zref, nodemask_t *nodes)
{
#ifdef CONFIG_NUMA
	return node_isset(zonelist_node_idx(zref), *nodes);
#else
	return 1;
#endif /* CONFIG_NUMA */
}

/* Returns the next zone at or below highest_zoneidx in a zonelist */
struct zoneref *next_zones_zonelist(struct zoneref *z,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes,
					struct zone **zone)
{
	/*
	 * Find the next suitable zone to use for the allocation.
	 * Only filter based on nodemask if it's set
	 */
	if (likely(nodes == NULL))
		while (zonelist_zone_idx(z) > highest_zoneidx)
			z++;
	else
		while (zonelist_zone_idx(z) > highest_zoneidx ||
				(z->zone && !zref_in_nodemask(z, nodes)))
			z++;

	*zone = zonelist_zone(z);
	return z;
}

#ifdef CONFIG_ARCH_HAS_HOLES_MEMORYMODEL
int memmap_valid_within(unsigned long pfn,
					struct page *page, struct zone *zone)
{
	if (page_to_pfn(page) != pfn)
		return 0;

	if (page_zone(page) != zone)
		return 0;

	return 1;
}
#endif /* CONFIG_ARCH_HAS_HOLES_MEMORYMODEL */

void setup_zone_gang(struct gang_set *gs, struct zone *zone, struct gang *gang)
{
	enum lru_list lru;

	gang->zone = zone;
	gang->set = gs;
	spin_lock_init(&gang->lru_lock);
	for_each_lru(lru) {
		INIT_LIST_HEAD(&gang->lru[lru].list);
		gang->lru[lru].nr_pages = 0;
	}
}

#ifdef CONFIG_MEMORY_GANGS

void add_zone_gang(struct zone *zone, struct gang *gang)
{
	unsigned long flags;

	spin_lock_irqsave(&zone->gangs_lock, flags);
	list_add_tail_rcu(&gang->list, &zone->gangs);
	list_add_tail(&gang->rr_list, &zone->gangs_rr);
	zone->nr_gangs++;
	spin_unlock_irqrestore(&zone->gangs_lock, flags);
}

static void del_zone_gang(struct zone *zone, struct gang *gang)
{
	unsigned long flags;
	enum lru_list lru;

	for_each_lru(lru) {
		BUG_ON(!list_empty(&gang->lru[lru].list));
		if (gang->lru[lru].nr_pages) {
			printk(KERN_EMERG "gang leak:%ld lru:%d gang:%p\n",
					gang->lru[lru].nr_pages, lru, gang);
			add_taint(TAINT_CRAP);
		}
	}

	spin_lock_irqsave(&zone->gangs_lock, flags);
	list_del_rcu(&gang->list);
	list_del(&gang->rr_list);
	zone->nr_gangs--;
	spin_unlock_irqrestore(&zone->gangs_lock, flags);
}

#ifdef CONFIG_MEMORY_GANGS_MIGRATION
static void init_gangs_migration_work(struct gang_set *gs);
#else
static inline void init_gangs_migration_work(struct gang_set *gs) { }
#endif

int alloc_mem_gangs(struct gang_set *gs)
{
	struct zone *zone;
	struct gang *gang;
	int node;

	memset(gs, 0, sizeof(struct gang_set));

	gs->gangs = kzalloc(nr_node_ids * sizeof(struct gang *), GFP_KERNEL);
	if (!gs->gangs)
		goto noarr;

	for_each_online_node(node) {
		gs->gangs[node] = kzalloc_node(sizeof(struct gang)*MAX_NR_ZONES,
						GFP_KERNEL, node);
		if (!gs->gangs[node])
			goto nomem;
	}

	for_each_populated_zone(zone) {
		gang = mem_zone_gang(gs, zone);
		setup_zone_gang(gs, zone, gang);
	}

	init_gangs_migration_work(gs);

	return 0;

nomem:
	free_mem_gangs(gs);
noarr:
	return -ENOMEM;
}

void free_mem_gangs(struct gang_set *gs)
{
	int node;

	for_each_node(node)
		kfree(gs->gangs[node]);
	kfree(gs->gangs);
}

void add_mem_gangs(struct gang_set *gs)
{
	struct zone *zone;

	for_each_populated_zone(zone)
		add_zone_gang(zone, mem_zone_gang(gs, zone));
}

#define MAX_MOVE_BATCH	256

static void move_gang_pages(struct gang *gang, struct gang *dst_gang)
{
	enum lru_list lru;
	int restart, wait;
	struct user_beancounter *src_ub = get_gang_ub(gang);
	struct user_beancounter *dst_ub = get_gang_ub(dst_gang);
	LIST_HEAD(pages_to_wait);
	LIST_HEAD(pages_to_free);

again:
	restart = wait = 0;
	for_each_lru(lru) {
		struct page *page, *next;
		LIST_HEAD(list);
		unsigned long nr_pages = 0;
		unsigned batch = 0;

		spin_lock_irq(&gang->lru_lock);
		list_splice(&gang->lru[lru].list, &list);
		list_for_each_entry_safe_reverse(page, next, &list, lru) {
			int numpages = hpage_nr_pages(page);

			if (batch >= MAX_MOVE_BATCH) {
				restart = 1;
				break;
			}
			if (!get_page_unless_zero(page)) {
				list_move(&page->lru, &pages_to_wait);
				restart = wait = 1;
				continue;
			}
			batch++;
			nr_pages += numpages;
			ClearPageLRU(page);
			set_page_gang(page, dst_gang);
		}
		list_cut_position(&gang->lru[lru].list, &list, &page->lru);
		list_splice_init(&pages_to_wait, &gang->lru[lru].list);
		gang->lru[lru].nr_pages -= nr_pages;
		spin_unlock_irq(&gang->lru_lock);

		if (!nr_pages)
			continue;

#ifdef CONFIG_BC_SWAP_ACCOUNTING
		if (!is_file_lru(lru)) {
			list_for_each_entry(page, &list, lru) {
				if (PageSwapCache(page)) {
					lock_page(page);
					ub_unuse_swap_page(page);
					unlock_page(page);
				}
			}
		}
#endif

		uncharge_beancounter_fast(src_ub, UB_PHYSPAGES, nr_pages);
		charge_beancounter_fast(dst_ub, UB_PHYSPAGES, nr_pages, UB_FORCE);

		spin_lock_irq(&dst_gang->lru_lock);
		dst_gang->lru[lru].nr_pages += nr_pages;
		list_for_each_entry_safe(page, next, &list, lru) {
			SetPageLRU(page);
			if (unlikely(put_page_testzero(page))) {
				__ClearPageLRU(page);
				del_page_from_lru(dst_gang, page);
				gang_del_user_page(page);
				list_add(&page->lru, &pages_to_free);
			}
		}
		list_splice(&list, &dst_gang->lru[lru].list);
		spin_unlock_irq(&dst_gang->lru_lock);

		list_for_each_entry_safe(page, next, &pages_to_free, lru) {
			list_del(&page->lru);
			VM_BUG_ON(PageTail(page));
			if (PageCompound(page))
				get_compound_page_dtor(page)(page);
			else
				free_hot_page(page);
		}
	}
	if (wait)
		schedule_timeout_uninterruptible(1);
	if (restart)
		goto again;
}

void splice_mem_gangs(struct gang_set *gs, struct gang_set *target)
{
	struct zone *zone;

	cancel_gangs_migration(gs);

	lru_add_drain_all();

	for_each_populated_zone(zone)
		move_gang_pages(mem_zone_gang(gs, zone),
				mem_zone_gang(target, zone));
}

void del_mem_gangs(struct gang_set *gs)
{
	struct zone *zone;

	for_each_populated_zone(zone)
		del_zone_gang(zone, mem_zone_gang(gs, zone));
}

void gang_page_stat(struct gang_set *gs, nodemask_t *nodemask,
		    unsigned long *stat)
{
	struct zoneref *z;
	struct zone *zone;
	struct gang *gang;
	enum lru_list lru;

	memset(stat, 0, sizeof(unsigned long) * NR_LRU_LISTS);
	for_each_zone_zonelist_nodemask(zone, z,
			node_zonelist(numa_node_id(), GFP_KERNEL),
			MAX_NR_ZONES - 1, nodemask) {
		gang = mem_zone_gang(gs, zone);
		for_each_lru(lru)
			stat[lru] += gang->lru[lru].nr_pages;
	}
}

void gang_show_state(struct gang_set *gs)
{
	struct zone *zone;
	struct gang *gang;
	unsigned long stat[NR_LRU_LISTS];

	for_each_populated_zone(zone) {
		gang = mem_zone_gang(gs, zone);
		printk("Node %d %s scan:%lu"
			" a_anon:%lu i_anon:%lu"
			" a_file:%lu i_file:%lu"
			" unevictable:%lu\n",
			zone_to_nid(zone), zone->name, gang->pages_scanned,
			gang->lru[LRU_ACTIVE_ANON].nr_pages,
			gang->lru[LRU_INACTIVE_ANON].nr_pages,
			gang->lru[LRU_ACTIVE_FILE].nr_pages,
			gang->lru[LRU_INACTIVE_FILE].nr_pages,
			gang->lru[LRU_UNEVICTABLE].nr_pages);
	}

	gang_page_stat(gs, NULL, stat);

	printk("Total %lu anon:%lu file:%lu"
			" a_anon:%lu i_anon:%lu"
			" a_file:%lu i_file:%lu"
			" unevictable:%lu\n",
			stat[LRU_ACTIVE_ANON] + stat[LRU_INACTIVE_ANON] +
			stat[LRU_ACTIVE_FILE] + stat[LRU_INACTIVE_FILE] +
			stat[LRU_UNEVICTABLE],
			stat[LRU_ACTIVE_ANON] + stat[LRU_INACTIVE_ANON],
			stat[LRU_ACTIVE_FILE] + stat[LRU_INACTIVE_FILE],
			stat[LRU_ACTIVE_ANON],
			stat[LRU_INACTIVE_ANON],
			stat[LRU_ACTIVE_FILE],
			stat[LRU_INACTIVE_FILE],
			stat[LRU_UNEVICTABLE]);
}

#else /* CONFIG_MEMORY_GANGS */

void gang_page_stat(struct gang_set *gs, nodemask_t *nodemask,
		    unsigned long *stat)
{
	enum lru_list lru;

	for_each_lru(lru)
		stat[lru] = global_page_state(NR_LRU_BASE + lru);
}

void gang_show_state(struct gang_set *gs) { }

#endif /* CONFIG_MEMORY_GANGS */

#ifdef CONFIG_MEMORY_GANGS_MIGRATION
static struct workqueue_struct **gangs_migration_wq;

unsigned int gangs_migration_max_isolate = 50;
unsigned int gangs_migration_min_batch = 100;
unsigned int gangs_migration_max_batch = 12800;
unsigned int gangs_migration_interval = 500;

static unsigned long isolate_gang_pages(struct gang *gang, enum lru_list lru,
		unsigned long nr_to_scan, struct list_head *pagelist)
{
	struct list_head *lru_list = &gang->lru[lru].list;
	unsigned long nr_isolated = 0;
	struct page *page, *next;
	int restart;
	LIST_HEAD(busy_pages);

again:
	restart = 0;
	spin_lock_irq(&gang->lru_lock);
	list_for_each_entry_safe_reverse(page, next, lru_list, lru) {
		if (nr_to_scan-- == 0)
			break;

		if (pin_mem_gang(gang))
			break;

		if (!get_page_unless_zero(page)) {
			list_move(&page->lru, &busy_pages);
			unpin_mem_gang(gang);
			continue;
		}

		if (unlikely(PageTransHuge(page))) {
			spin_unlock_irq(&gang->lru_lock);
			split_huge_page(page);
			put_page(page);
			restart = 1;
			spin_lock_irq(&gang->lru_lock);
			unpin_mem_gang(gang);
			break;
		}

		ClearPageLRU(page);
		del_page_from_lru_list(gang, page, lru);
		inc_zone_page_state(page, NR_ISOLATED_ANON +
				    page_is_file_cache(page));

		nr_isolated++;
		list_add(&page->lru, pagelist);
	}
	list_splice_init(&busy_pages, lru_list);
	spin_unlock_irq(&gang->lru_lock);

	if (restart)
		goto again;

	return nr_isolated;
}

static struct page *gangs_migration_new_page(struct page *page,
					     unsigned long private, int **x)
{
	struct gangs_migration_work *w = (void *)private;
	gfp_t gfp_mask = GFP_HIGHUSER_MOVABLE | __GFP_NORETRY;

	return __alloc_pages_nodemask(gfp_mask, 0,
			node_zonelist(w->preferred_node, gfp_mask),
			&w->dest_nodes);
}

static int __migrate_gangs(struct gang_set *gs, struct gangs_migration_work *w)
{
	struct zoneref *z;
	struct zone *zone;
	enum lru_list lru;
	nodemask_t cur_nodemask;
	LIST_HEAD(pagelist);
	unsigned long nr_to_scan, nr_isolated, nr_moved;
	int rc;

	nr_moved = 0;
	cur_nodemask = nodemask_of_node(w->cur_node);
	for_each_zone_zonelist_nodemask(zone, z,
			node_zonelist(w->cur_node, GFP_KERNEL),
			MAX_NR_ZONES - 1, &cur_nodemask) {
		struct gang *gang = mem_zone_gang(gs, zone);
		unsigned long left = gang->nr_migratepages;

		if (!left)
			continue;
		while (nr_moved < w->batch && left) {
			int empty = 1;

			for_each_lru(lru) {
				if (!gang->lru[lru].nr_pages)
					continue;
				empty = 0;

				nr_to_scan = min_t(unsigned long,
					left, gangs_migration_max_isolate);
				left -= nr_to_scan;

				nr_isolated = isolate_gang_pages(gang, lru,
						nr_to_scan, &pagelist);
				if (!nr_isolated)
					continue;
				rc = migrate_pages(&pagelist,
						gangs_migration_new_page,
						(unsigned long)w, false, true);
				if (rc < 0)
					return -1;
				nr_moved += nr_isolated - rc;
			}
			if (empty)
				left = 0;
		}
		gang->nr_migratepages = left;
		if (nr_moved >= w->batch)
			return 1;
	}
	return 0;
}

static void migrate_gangs(struct work_struct *work)
{
	struct delayed_work *dwork;
	struct gangs_migration_work *w;
	struct gang_set *gs;
	const struct cpumask *cpumask;
	int cpu, rc;
	unsigned long delay = 0;

	dwork = to_delayed_work(work);
	w = container_of(dwork, struct gangs_migration_work, dwork);
	gs = container_of(w, struct gang_set, migration_work);

	if (!node_online(w->cur_node)) {
		node_clear(w->cur_node, w->src_nodes);
		goto next;
	}

	cpu = task_cpu(current);
	cpumask = cpumask_of_node(w->cur_node);
	if (!cpumask_test_cpu(cpu, cpumask))
		set_cpus_allowed_ptr(current, cpumask);

	rc = __migrate_gangs(gs, w);
	if (rc < 0) {
		nodes_clear(w->src_nodes);
		return;
	}
	if (!rc)
		node_clear(w->cur_node, w->src_nodes);
next:
	if (!nodes_empty(w->src_nodes)) {
		w->cur_node = next_node(w->cur_node, w->src_nodes);
		if (w->cur_node >= MAX_NUMNODES) {
			w->cur_node = first_node(w->src_nodes);
			w->batch *= 2;
			if (w->batch > gangs_migration_max_batch)
				w->batch = gangs_migration_max_batch;
			delay = msecs_to_jiffies(gangs_migration_interval);
		}
		w->preferred_node = next_node(w->preferred_node, w->dest_nodes);
		if (w->preferred_node >= MAX_NUMNODES)
			w->preferred_node = first_node(w->dest_nodes);
		queue_delayed_work(gangs_migration_wq[w->cur_node],
				   dwork, delay);
	}
}

static void __schedule_gangs_migration(struct gang_set *gs,
				       struct gangs_migration_work *w)
{
	struct zoneref *z;
	struct zone *zone;
	enum lru_list lru;

	for_each_zone_zonelist_nodemask(zone, z,
			node_zonelist(numa_node_id(), GFP_KERNEL),
			MAX_NR_ZONES - 1, &w->src_nodes) {
		struct gang *gang = mem_zone_gang(gs, zone);

		gang->nr_migratepages = 0;
		for_each_lru(lru) {
			gang->nr_migratepages +=
				gang->lru[lru].nr_pages;
		}
		gang->nr_migratepages *= NR_LRU_LISTS;
	}
	w->cur_node = first_node(w->src_nodes);
	w->preferred_node = first_node(w->dest_nodes);
	w->batch = gangs_migration_min_batch;
	queue_delayed_work(gangs_migration_wq[w->cur_node], &w->dwork, 0);
}

/* Returns 0 if migration was already scheduled, non-zero otherwise */
int schedule_gangs_migration(struct gang_set *gs,
		const nodemask_t *src_nodes, const nodemask_t *dest_nodes)
{
	struct gangs_migration_work *w = &gs->migration_work;
	nodemask_t tmp;
	int ret = 0;

	mutex_lock(&w->lock);
	if (!nodes_empty(w->src_nodes))
		goto out;
	cancel_delayed_work_sync(&w->dwork);
	nodes_and(w->dest_nodes, *dest_nodes, node_online_map);
	if (!nodes_empty(w->dest_nodes)) {
		nodes_andnot(tmp, *src_nodes, *dest_nodes);
		nodes_and(w->src_nodes, tmp, node_online_map);
		if (!nodes_empty(w->src_nodes))
			__schedule_gangs_migration(gs, w);
	}
	ret = 1;
out:
	mutex_unlock(&w->lock);
	return ret;
}

/* Returns 0 if migration was not pending, non-zero otherwise. */
int cancel_gangs_migration(struct gang_set *gs)
{
	struct gangs_migration_work *w = &gs->migration_work;
	int ret = 0;

	mutex_lock(&w->lock);
	if (nodes_empty(w->src_nodes))
		goto out;
	cancel_delayed_work_sync(&w->dwork);
	nodes_clear(w->src_nodes);
	ret = 1;
out:
	mutex_unlock(&w->lock);
	return ret;
}

int gangs_migration_pending(struct gang_set *gs, nodemask_t *pending)
{
	struct gangs_migration_work *w = &gs->migration_work;
	int ret;

	mutex_lock(&w->lock);
	if (pending)
		*pending = w->src_nodes;
	ret = !nodes_empty(w->src_nodes);
	mutex_unlock(&w->lock);
	return ret;
}

static void init_gangs_migration_work(struct gang_set *gs)
{
	struct gangs_migration_work *w = &gs->migration_work;

	INIT_DELAYED_WORK(&w->dwork, migrate_gangs);
	nodes_clear(w->src_nodes);
	mutex_init(&w->lock);
}

static __init int init_gangs_migration_wq(void)
{
	int node;
	char name[32];

	init_gangs_migration_work(&init_gang_set);

	if (nr_node_ids == 1)
		return 0;

	gangs_migration_wq = kcalloc(nr_node_ids,
			sizeof(struct workqueue_struct *), GFP_KERNEL);
	BUG_ON(!gangs_migration_wq);

	for_each_node(node) {
		snprintf(name, sizeof(name), "gsmigration/%d", node);
		gangs_migration_wq[node] = create_singlethread_workqueue(name);
		BUG_ON(!gangs_migration_wq[node]);
	}

	return 0;
}
late_initcall(init_gangs_migration_wq);

static int gangs_migration_batch_constraints(void)
{
	if (gangs_migration_min_batch <= 0 ||
	    gangs_migration_min_batch > gangs_migration_max_batch)
		return -EINVAL;
	return 0;
}

int gangs_migration_batch_sysctl_handler(struct ctl_table *table,
		int write, void __user *buffer, size_t *lenp, loff_t *ppos)
{
	static DEFINE_MUTEX(lock);
	unsigned int old_min, old_max;
	int err;

	mutex_lock(&lock);

	old_min = gangs_migration_min_batch;
	old_max = gangs_migration_max_batch;

	err = proc_dointvec(table, write, buffer, lenp, ppos);
	if (err || !write)
		goto out;

	err = gangs_migration_batch_constraints();
	if (err) {
		gangs_migration_min_batch = old_min;
		gangs_migration_max_batch = old_max;
	}

out:
	mutex_unlock(&lock);
	return err;
}
#endif /* CONFIG_MEMORY_GANGS_MIGRATION */

struct gang *init_gang_array[MAX_NUMNODES];

#ifndef CONFIG_BC_RSS_ACCOUNTING
struct gang_set init_gang_set = {
#ifdef CONFIG_MEMORY_GANGS
	.gangs = init_gang_array,
#endif
};
#endif
