#include <linux/module.h>
#include <linux/fs.h>

#ifdef CONFIG_CGROUP_DEVICE
extern int devcgroup_inode_permission(struct inode *inode, int mask);
extern int devcgroup_inode_mknod(int mode, dev_t dev);
extern int devcgroup_device_visible(int type, int major,
		int start_minor, int nr_minors);
#else
static inline int devcgroup_inode_permission(struct inode *inode, int mask)
{ return 0; }
static inline int devcgroup_inode_mknod(int mode, dev_t dev)
{ return 0; }
static inline int devcgroup_device_visible(int type, int major,
		int start_minor, int nr_minors)
{ return 0; }
#endif
