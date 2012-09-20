#include <linux/sched.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/interrupt.h>
#include <linux/slab.h>

#include <linux/ploop/ploop_if.h>
#include "io_direct_events.h"
#include "io_direct_map.h"

/* Part of io_direct shared between all the devices.
 * No way this code is good. But it is the best, which we can do
 * not modifying core.
 *
 * Keep track of images opened by ploop. Maintain shared extent
 * maps for shared images, which are open read-only. Top level
 * deltas, which are open for write, are open exclusively.
 *
 * Also take care about setting/clearing S_SWAPFILE and setting
 * mapping gfp mask to GFP_NOFS.
 */

struct ploop_mapping
{
	struct list_head	list;
	struct address_space	* mapping;
	int			readers;
	unsigned long		saved_gfp_mask;

	struct extent_map_tree	extent_root;
};

static LIST_HEAD(ploop_mappings);
static DEFINE_SPINLOCK(ploop_mappings_lock);

static void extent_map_tree_init(struct extent_map_tree *tree);
static int drop_extent_map(struct extent_map_tree *tree);
static int remove_extent_mapping(struct extent_map_tree *tree, struct extent_map *em);



/*
 * ploop_dio_* functions must be called with i_mutex taken.
 */

struct extent_map_tree *
ploop_dio_open(struct file * file, int rdonly)
{
	int err;
	struct ploop_mapping *m, *pm;
	struct address_space * mapping = file->f_mapping;

	pm = kzalloc(sizeof(struct ploop_mapping), GFP_KERNEL);

	err = 0;
	spin_lock(&ploop_mappings_lock);
	list_for_each_entry(m, &ploop_mappings, list) {
		if (m->mapping == mapping) {
			if (rdonly) {
				if (m->readers < 0)
					err = -ETXTBSY;
				else
					m->readers++;
			} else {
				if (m->readers)
					err = -EBUSY;
				else
					m->readers = -1;
			}

out_unlock:
			spin_unlock(&ploop_mappings_lock);
			if (pm)
				kfree(pm);
			return err ? ERR_PTR(err) : &m->extent_root;
		}
	}

	if (pm == NULL) {
		err = -ENOMEM;
		goto out_unlock;
	}

	if (mapping->host->i_flags & S_SWAPFILE) {
		err = -EBUSY;
		goto out_unlock;
	}

	pm->mapping = mapping;
	extent_map_tree_init(&pm->extent_root);
	pm->extent_root.mapping = mapping;
	pm->readers = rdonly ? 1 : -1;
	list_add(&pm->list, &ploop_mappings);
	mapping->host->i_flags |= S_SWAPFILE;

	pm->saved_gfp_mask = mapping_gfp_mask(mapping);
	mapping_set_gfp_mask(mapping,
			     pm->saved_gfp_mask & ~__GFP_FS);

	spin_unlock(&ploop_mappings_lock);

	if (strcmp(mapping->host->i_sb->s_type->name, "pcss") == 0) {
		struct ploop_xops xops;
		if (file->f_op->unlocked_ioctl) {
			mm_segment_t fs = get_fs();

			set_fs(KERNEL_DS);
			xops.magic = 0;
			err = file->f_op->unlocked_ioctl(file, PLOOP_IOC_INTERNAL, (long)&xops);
			set_fs(fs);
			if (err == 0 && xops.magic == PLOOP_INTERNAL_MAGIC)
				pm->extent_root._get_extent = xops.get_extent;
		}
	}
	return &pm->extent_root;
}

int
ploop_dio_close(struct address_space * mapping, int rdonly)
{
	struct ploop_mapping *m, *pm = NULL;

	spin_lock(&ploop_mappings_lock);
	list_for_each_entry(m, &ploop_mappings, list) {
		if (m->mapping == mapping) {
			if (rdonly) {
				m->readers--;
			} else {
				BUG_ON(m->readers != -1);
				m->readers = 0;
			}

			if (m->readers == 0) {
				mapping->host->i_flags &= ~S_SWAPFILE;
				list_del(&m->list);
				pm = m;
			}
			break;
		}
	}
	spin_unlock(&ploop_mappings_lock);

	if (pm) {
		drop_extent_map(&pm->extent_root);
		kfree(pm);
		return 0;
	}
	return -ENOENT;
}

void ploop_dio_downgrade(struct address_space * mapping)
{
	struct ploop_mapping * m;

	spin_lock(&ploop_mappings_lock);
	list_for_each_entry(m, &ploop_mappings, list) {
		if (m->mapping == mapping) {
			BUG_ON(m->readers != -1);
			m->readers = 1;
			break;
		}
	}
	spin_unlock(&ploop_mappings_lock);
}

int ploop_dio_upgrade(struct address_space * mapping)
{
	struct ploop_mapping * m;
	int err = -ESRCH;

	spin_lock(&ploop_mappings_lock);
	list_for_each_entry(m, &ploop_mappings, list) {
		if (m->mapping == mapping) {
			err = -EBUSY;
			if (m->readers == 1) {
				m->readers = -1;
				err = 0;
			}
			break;
		}
	}
	spin_unlock(&ploop_mappings_lock);
	return err;
}


/* The rest of the file is written by Jens Axboe.
 * I just fixed a few of bugs (requests not aligned at fs block size
 * due to direct-io aligned to 512) and truncated some useless functionality.
 *
 * In any case, it must be remade: not only because of GPL, but also
 * because it is not good.
 */

static struct kmem_cache *extent_map_cache;

int __init extent_map_init(void)
{
	extent_map_cache = kmem_cache_create("ploop_itree",
						sizeof(struct extent_map), 0,
						SLAB_MEM_SPREAD, NULL
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
						, NULL
#endif
						);
	if (!extent_map_cache)
		return -ENOMEM;
	return 0;
}

void extent_map_exit(void)
{
	if (extent_map_cache)
		kmem_cache_destroy(extent_map_cache);
}

static void extent_map_tree_init(struct extent_map_tree *tree)
{
	tree->map.rb_node = NULL;
	rwlock_init(&tree->lock);
}

struct extent_map *alloc_extent_map(gfp_t mask)
{
	struct extent_map *em;

	em = kmem_cache_alloc(extent_map_cache, GFP_NOFS);
	if (em)
		atomic_set(&em->refs, 1);
	return em;
}

void extent_put(struct extent_map *em)
{
	if (!em)
		return;
	if (atomic_dec_and_test(&em->refs))
		kmem_cache_free(extent_map_cache, em);
}

static struct rb_node *tree_insert(struct rb_root *root, sector_t start,
				   sector_t end, struct rb_node *node)
{
	struct rb_node ** p = &root->rb_node;
	struct rb_node * parent = NULL;
	struct extent_map *entry;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct extent_map, rb_node);

		if (end <= entry->start)
			p = &(*p)->rb_left;
		else if (start >= entry->end)
			p = &(*p)->rb_right;
		else
			return parent;
	}

	rb_link_node(node, parent, p);
	rb_insert_color(node, root);
	return NULL;
}

/* Find extent which contains "offset". If there is no such extent,
 * prev_ret is the first extent following "offset".
 */
static struct rb_node *__tree_search(struct rb_root *root, sector_t offset,
				     struct rb_node **prev_ret)
{
	struct rb_node * n = root->rb_node;
	struct rb_node *prev = NULL;
	struct extent_map *entry;
	struct extent_map *prev_entry = NULL;

	while (n) {
		entry = rb_entry(n, struct extent_map, rb_node);
		prev = n;
		prev_entry = entry;

		if (offset < entry->start)
			n = n->rb_left;
		else if (offset >= entry->end)
			n = n->rb_right;
		else
			return n;
	}
	if (!prev_ret)
		return NULL;

	while (prev && offset >= prev_entry->end) {
		prev = rb_next(prev);
		prev_entry = rb_entry(prev, struct extent_map, rb_node);
	}
	*prev_ret = prev;
	return NULL;
}

/* Find the first extent which could intersect a range starting at offset.
 * Probably, it does not contain offset.
 */
static inline struct rb_node *tree_search(struct rb_root *root, sector_t offset)
{
	struct rb_node *prev;
	struct rb_node *ret;
	ret = __tree_search(root, offset, &prev);
	if (!ret)
		return prev;
	return ret;
}

static int tree_delete(struct rb_root *root, sector_t offset)
{
	struct rb_node *node;

	node = __tree_search(root, offset, NULL);
	if (!node)
		return -ENOENT;
	rb_erase(node, root);
	return 0;
}

static int mergable_maps(struct extent_map *prev, struct extent_map *next)
{
	if (prev->end == next->start &&
	    next->block_start == extent_map_block_end(prev))
		return 1;
	return 0;
}

/*
 * add_extent_mapping tries a simple forward/backward merge with existing
 * mappings.  The extent_map struct passed in will be inserted into
 * the tree directly (no copies made, just a reference taken).
 */
static int add_extent_mapping(struct extent_map_tree *tree,
			      struct extent_map *em)
{
	int ret = 0;
	struct rb_node *rb;

	write_lock_irq(&tree->lock);

	do {
		rb = tree_insert(&tree->map, em->start, em->end, &em->rb_node);
		/* A part of this extent can be in tree */
		if (rb) {
			struct extent_map *tmp =
				rb_entry(rb, struct extent_map, rb_node);
			BUG_ON(tmp->block_start - tmp->start !=
					em->block_start - em->start);
			if (tmp->start <= em->start &&
			    tmp->end >= em->end) {
				ret =  -EEXIST;
				goto out;
			}
			if (tmp->start < em->start) {
				em->start = tmp->start;
				em->block_start = tmp->block_start;
			}
			if (tmp->end > em->end)
				em->end = tmp->end;
			rb_erase(rb, &tree->map);
			extent_put(tmp);
		}
	} while (rb);

	atomic_inc(&em->refs);
	if (em->start != 0) {
		rb = rb_prev(&em->rb_node);
		if (rb) {
			struct extent_map *merge;

			merge = rb_entry(rb, struct extent_map, rb_node);
			if (mergable_maps(merge, em)) {
				em->start = merge->start;
				em->block_start = merge->block_start;
				rb_erase(&merge->rb_node, &tree->map);
				extent_put(merge);
			}
		}
	}
	rb = rb_next(&em->rb_node);
	if (rb) {
		struct extent_map *merge;

		merge = rb_entry(rb, struct extent_map, rb_node);
		if (mergable_maps(em, merge)) {
			em->end = merge->end;
			rb_erase(&merge->rb_node, &tree->map);
			extent_put(merge);
		}
	}

	trace_add_extent_mapping(em);
out:
	write_unlock_irq(&tree->lock);
	return ret;
}

struct extent_map *
extent_lookup(struct extent_map_tree *tree, sector_t start)
{
	struct extent_map *em = NULL;
	struct rb_node *rb_node;

	read_lock(&tree->lock);
	rb_node = __tree_search(&tree->map, start, NULL);
	if (rb_node) {
		em = rb_entry(rb_node, struct extent_map, rb_node);
		atomic_inc(&em->refs);
	}
	read_unlock(&tree->lock);
	return em;
}

/*
 * lookup_extent_mapping returns the first extent_map struct in the
 * tree that intersects the [start, start+len) range.  There may
 * be additional objects in the tree that intersect, so check the object
 * returned carefully to make sure you don't need additional lookups.
 */
static struct extent_map *
lookup_extent_mapping(struct extent_map_tree *tree, sector_t start, sector_t len)
{
	struct extent_map *em;
	struct rb_node *rb_node;

	read_lock(&tree->lock);
	rb_node = tree_search(&tree->map, start);
	if (!rb_node) {
		em = NULL;
		goto out;
	}
	em = rb_entry(rb_node, struct extent_map, rb_node);
	if (em->end <= start || em->start >= start + len) {
		em = NULL;
		goto out;
	}
	atomic_inc(&em->refs);

out:
	read_unlock(&tree->lock);
	return em;
}

/*
 * removes an extent_map struct from the tree.  No reference counts are
 * dropped, and no checks are done to  see if the range is in use
 */
static int remove_extent_mapping(struct extent_map_tree *tree, struct extent_map *em)
{
	int ret;

	write_lock_irq(&tree->lock);
	ret = tree_delete(&tree->map, em->start);
	write_unlock_irq(&tree->lock);
	return ret;
}

static struct extent_map *__map_extent_get_extent(struct extent_map_tree *tree,
						  struct address_space *mapping,
						  sector_t start, sector_t len, int create,
						  gfp_t gfp_mask)
{
	struct inode *inode = mapping->host;
	struct extent_map *em;
	sector_t nstart, result;
	int ret;

again:
	em = lookup_extent_mapping(tree, start, len);
	if (em) {
		if (em->start <= start && em->end >= start + len)
			return em;

		/*
		 * we may have found an extent that starts after the
		 * requested range.  Double check and alter the length
		 * appropriately
		 */
		if (em->start > start) {
			len = em->start - start;
		} else if (!create) {
			return em;
		}
		extent_put(em);
	}
	BUG_ON(gfp_mask & GFP_ATOMIC);

	em = alloc_extent_map(gfp_mask);
	if (!em)
		return ERR_PTR(-ENOMEM);

	/*
	 * FIXME if there are errors later on, we end up exposing stale
	 * data on disk while filling holes.
	 *
	 * _XXX_ Danger! len is reduced above, therefore _get_extent
	 * does not allocate all that we need. It works only with pcss
	 * and only when cluster size <= pcss block size and allocation
	 * is aligned. If we relax those conditions, the code must be fixed.
	 */
	ret = tree->_get_extent(inode, start, len, &nstart, &result, create);
	if (ret < 0) {
		extent_put(em);
		return ERR_PTR(ret);
	}

	em->start = nstart;
	em->end = nstart + ret;
	em->block_start = result;

	ret = add_extent_mapping(tree, em);
	if (ret == -EEXIST) {
		extent_put(em);
		goto again;
	}
	return em;
}

static struct extent_map *__map_extent_bmap(struct extent_map_tree *tree,
				       struct address_space *mapping,
				       sector_t start, sector_t len, gfp_t gfp_mask)
{
	struct inode *inode = mapping->host;
	struct extent_map *em;
	struct fiemap_extent_info fieinfo;
	struct fiemap_extent fi_extent;
	mm_segment_t old_fs;
	int ret;

again:
	em = lookup_extent_mapping(tree, start, len);
	if (em) {
		/*
		 * we may have found an extent that starts after the
		 * requested range.  Double check and alter the length
		 * appropriately
		 */
		if (em->start > start) {
			len = em->start - start;
		} else {
			return em;
		}
		extent_put(em);
	}

	BUG_ON(gfp_mask & GFP_ATOMIC);

	if (!inode->i_op->fiemap)
		return ERR_PTR(-EINVAL);

	em = alloc_extent_map(gfp_mask);
	if (!em)
		return ERR_PTR(-ENOMEM);

	fieinfo.fi_extents_start = &fi_extent;
	fieinfo.fi_extents_max = 1;
	fieinfo.fi_flags = 0;
	fieinfo.fi_extents_mapped = 0;
	fi_extent.fe_flags = 0;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = inode->i_op->fiemap(inode, &fieinfo, start << 9, 1);
	set_fs(old_fs);

	if (ret) {
		extent_put(em);
		return ERR_PTR(ret);
	}

	if (fieinfo.fi_extents_mapped != 1) {
		extent_put(em);
		return ERR_PTR(-EINVAL);
	}

	em->start = fi_extent.fe_logical >> 9;
	em->end = (fi_extent.fe_logical + fi_extent.fe_length) >> 9;

	if (fi_extent.fe_flags & FIEMAP_EXTENT_UNWRITTEN) {
		em->block_start = BLOCK_UNINIT;
	} else {
		em->block_start = fi_extent.fe_physical >> 9;

		ret = add_extent_mapping(tree, em);
		if (ret == -EEXIST) {
			extent_put(em);
			goto again;
		}
	}
	return em;
}

static struct extent_map *__map_extent(struct extent_map_tree *tree,
				       struct address_space *mapping,
				       sector_t start, sector_t len, int create,
				       gfp_t gfp_mask, get_block_t get_block)
{
	if (tree->_get_extent)
		return __map_extent_get_extent(tree, mapping, start, len, create,
					       gfp_mask);
	if (create)
		/* create flag not supported by bmap implementation */
		return ERR_PTR(-EINVAL);

	return __map_extent_bmap(tree, mapping, start,len, gfp_mask);
}

struct extent_map *map_extent_get_block(struct extent_map_tree *tree,
					struct address_space *mapping,
					sector_t start, sector_t len, int create,
					gfp_t gfp_mask, get_block_t get_block)
{
	struct extent_map *em;
	sector_t last;
	sector_t map_ahead_len = 0;

	em = __map_extent(tree, mapping, start, len, create,
			  gfp_mask, get_block);

	/*
	 * if we're doing a write or we found a large extent, return it
	 */
	if (IS_ERR(em) || !em || create || start + len < em->end) {
		return em;
	}

	/*
	 * otherwise, try to walk forward a bit and see if we can build
	 * something bigger.
	 */
	do {
		last = em->end;
		extent_put(em);
		em = __map_extent(tree, mapping, last, len, create,
				  gfp_mask, get_block);
		if (IS_ERR(em) || !em)
			break;
		map_ahead_len += em->end - last;
	} while (em->start <= start && start + len <= em->end &&
		 map_ahead_len < 1024);

	/* make sure we return the extent for this range */
	if (!em || IS_ERR(em) || em->start > start ||
	    start + len > em->end) {
		if (em && !IS_ERR(em))
			extent_put(em);
		em = __map_extent(tree, mapping, start, len, create,
				  gfp_mask, get_block);
	}
	return em;
}


struct extent_map *extent_lookup_create(struct extent_map_tree *tree,
					sector_t start, sector_t len)
{
	return map_extent_get_block(tree, tree->mapping,
				    start, len, 0, mapping_gfp_mask(tree->mapping),
				    NULL);
}

static int drop_extent_map(struct extent_map_tree *tree)
{
	struct extent_map *em;
	struct rb_node * node;

	write_lock_irq(&tree->lock);
	while ((node = tree->map.rb_node) != NULL) {
		em = rb_entry(node, struct extent_map, rb_node);
		rb_erase(node, &tree->map);
		extent_put(em);
	}
	write_unlock_irq(&tree->lock);
	return 0;
}

void trim_extent_mappings(struct extent_map_tree *tree, sector_t start)
{
	struct extent_map *em;

	while ((em = lookup_extent_mapping(tree, start, ((sector_t)(-1ULL)) - start))) {
		remove_extent_mapping(tree, em);
		/* once for us */
		extent_put(em);
		/* _XXX_ This cannot be correct in the case of concurrent lookups */
		/* once for the tree */
		extent_put(em);
	}
}


void dump_extent_map(struct extent_map_tree *tree)
{
	struct rb_node * r = rb_first(&tree->map);

	while (r) {
		struct extent_map *em0 = rb_entry(r, struct extent_map, rb_node);
		printk("N=%ld %ld -> %ld\n", (long)em0->start, (long)(em0->end - em0->start), (long)em0->block_start);
		r = rb_next(r);
	}
}

