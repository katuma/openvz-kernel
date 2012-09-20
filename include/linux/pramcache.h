#ifndef _LINUX_PRAMCACHE_H
#define _LINUX_PRAMCACHE_H

struct inode;
struct super_block;

#ifdef CONFIG_PRAMCACHE
extern void pramcache_load(struct super_block *sb);
extern void pramcache_populate_inode(struct inode *inode);
extern void pramcache_save_page_cache(struct super_block *sb);
extern void pramcache_save_bdev_cache(struct super_block *sb);
#else
static inline void pramcache_load(struct super_block *sb) { }
static inline void pramcache_populate_inode(struct inode *inode) { }
static inline void pramcache_save_page_cache(struct super_block *sb) { }
static inline void pramcache_save_bdev_cache(struct super_block *sb) { }
#endif /* CONFIG_PRAMCACHE */

#endif /* _LINUX_PRAMCACHE_H */
