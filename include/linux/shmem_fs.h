#ifndef __SHMEM_FS_H
#define __SHMEM_FS_H

#include <linux/swap.h>
#include <linux/mempolicy.h>
#include <linux/percpu_counter.h>

/* inode in-kernel data */

#define SHMEM_NR_DIRECT 16

struct shmem_inode_info {
	spinlock_t		lock;
	unsigned long		flags;
	unsigned long		alloced;	/* data pages alloced to file */
	unsigned long		swapped;	/* subtotal assigned to swap */
	unsigned long		next_index;	/* highest alloced index + 1 */
	struct shared_policy	policy;		/* NUMA memory alloc policy */
	struct page		*i_indirect;	/* top indirect blocks page */
	swp_entry_t		i_direct[SHMEM_NR_DIRECT]; /* first blocks */
	struct list_head	swaplist;	/* chain of maybes on swap */
	struct inode		vfs_inode;
#ifdef CONFIG_BEANCOUNTERS
	struct user_beancounter	*shmi_ub;
#endif
};

struct shmem_sb_info {
	unsigned long max_blocks;   /* How many blocks are allowed */
	struct percpu_counter used_blocks;  /* How many are allocated */
	unsigned long max_inodes;   /* How many inodes are allowed */
	unsigned long free_inodes;  /* How many are left for allocation */
	spinlock_t stat_lock;	    /* Serialize shmem_sb_info changes */
	uid_t uid;		    /* Mount uid for root directory */
	gid_t gid;		    /* Mount gid for root directory */
	mode_t mode;		    /* Mount mode for root directory */
	struct mempolicy *mpol;     /* default memory policy for mappings */
};

static inline struct shmem_inode_info *SHMEM_I(struct inode *inode)
{
	return container_of(inode, struct shmem_inode_info, vfs_inode);
}

extern int init_tmpfs(void);
extern int shmem_fill_super(struct super_block *sb, void *data, int silent);

#ifdef CONFIG_TMPFS_POSIX_ACL
int shmem_check_acl(struct inode *, int);
int shmem_acl_init(struct inode *, struct inode *);

extern struct xattr_handler shmem_xattr_acl_access_handler;
extern struct xattr_handler shmem_xattr_acl_default_handler;

extern struct generic_acl_operations shmem_acl_ops;

#else
static inline int shmem_acl_init(struct inode *inode, struct inode *dir)
{
	return 0;
}
#endif  /* CONFIG_TMPFS_POSIX_ACL */

int shmem_insertpage(struct inode * inode, unsigned long index,
		     swp_entry_t swap);
int install_shmem_page(struct vm_area_struct *vma,
		       unsigned long addr, struct page *page);
int is_shmem_vma(struct vm_area_struct *vma);

#endif
