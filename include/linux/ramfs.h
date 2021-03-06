#ifndef _LINUX_RAMFS_H
#define _LINUX_RAMFS_H

struct ramfs_mount_opts {
	umode_t mode;
};

struct ramfs_fs_info {
	struct ramfs_mount_opts mount_opts;
#ifdef CONFIG_PRAMFS
	int pram_load;
	int pram_save;
#define PRAM_FS_NAME_MAX	256	/* including nul */
	char pram_name[PRAM_FS_NAME_MAX];
#endif
};

struct inode *ramfs_get_inode(struct super_block *sb, int mode, dev_t dev);
extern int ramfs_get_sb(struct file_system_type *fs_type,
	 int flags, const char *dev_name, void *data, struct vfsmount *mnt);
extern int ramfs_fill_super(struct super_block * sb, void * data, int silent);

#ifndef CONFIG_MMU
extern int ramfs_nommu_expand_for_mapping(struct inode *inode, size_t newsize);
extern unsigned long ramfs_nommu_get_unmapped_area(struct file *file,
						   unsigned long addr,
						   unsigned long len,
						   unsigned long pgoff,
						   unsigned long flags);

extern int ramfs_nommu_mmap(struct file *file, struct vm_area_struct *vma);
#endif

extern const struct file_operations ramfs_file_operations;
extern const struct vm_operations_struct generic_file_vm_ops;
extern int __init init_rootfs(void);

#endif
