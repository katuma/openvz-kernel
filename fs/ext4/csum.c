/*
 * linux/fs/ext4/csum.c
 *
 * Automatic SHA-1 (FIPS 180-1) data checksummig
 *
 * Copyright (C) 2012 Parallels, inc.
 *
 * Author: Konstantin Khlebnikov
 *
 */

#include <linux/fs.h>
#include <linux/jbd2.h>
#include <linux/cryptohash.h>
#include <linux/namei.h>
#include <linux/init_task.h>	/* for init_cred */
#include "ext4.h"
#include "xattr.h"

#include <trace/events/ext4.h>

#define PFCACHE_MAX_PATH	(EXT4_DATA_CSUM_SIZE * 2 + 2)
static void pfcache_path(struct inode *inode, char *path)
{
	char *p;
	int i;

	/* like .git/objects hex[0]/hex[1..] */
	p = pack_hex_byte(path, EXT4_I(inode)->i_data_csum[0]);
	*p++ = '/';
	for ( i = 1 ; i < EXT4_DATA_CSUM_SIZE ; i++ )
		p = pack_hex_byte(p, EXT4_I(inode)->i_data_csum[i]);
	*p = 0;
}

/* require inode->i_mutex held or unreachable inode */
int ext4_open_pfcache(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	const struct cred *cur_cred;
	char path[PFCACHE_MAX_PATH];
	struct nameidata nd = {
		.flags = LOOKUP_STRICT,
		.last_type = LAST_ROOT,
	};
	int ret;

	if (!(ext4_test_inode_state(inode, EXT4_STATE_CSUM) &&
	      EXT4_I(inode)->i_data_csum_end < 0))
		return -ENODATA;

	if (!EXT4_SB(sb)->s_pfcache_root.mnt)
		return -ENODEV;

	spin_lock(&EXT4_SB(sb)->s_pfcache_lock);
	nd.path = EXT4_SB(sb)->s_pfcache_root;
	path_get(&nd.path);
	spin_unlock(&EXT4_SB(sb)->s_pfcache_lock);

	if (!nd.path.mnt)
		return -ENODEV;

	pfcache_path(inode, path);

	cur_cred = override_creds(&init_cred);
	/*
	 * Files in cache area must not have csum attributes or
	 * pfcache must be disabled for underlain filesystem,
	 * otherwise real lock-recursion can happens for i_mutex.
	 * Here we disable lockdep to avoid false-positive reports.
	 */
	lockdep_off();
	ret = path_walk(path, &nd);
	lockdep_on();
	revert_creds(cur_cred);
	if (ret)
		return ret;

	ret = open_inode_peer(inode, &nd.path, &init_cred);
	if (!ret)
		percpu_counter_inc(&EXT4_SB(inode->i_sb)->s_pfcache_peers);
	return ret;
}

/* require inode->i_mutex held or unreachable inode */
int ext4_close_pfcache(struct inode *inode)
{
	if (!inode->i_peer_file)
		return -ENOENT;
	close_inode_peer(inode);
	percpu_counter_dec(&EXT4_SB(inode->i_sb)->s_pfcache_peers);
	return 0;
}

/* under sb->s_umount write lock */
int ext4_relink_pfcache(struct super_block *sb, char *new_root)
{
	int old_root = !!EXT4_SB(sb)->s_pfcache_root.mnt;
	struct inode *inode, *old_inode = NULL;
	char path[PFCACHE_MAX_PATH];
	struct nameidata nd;
	struct file *file;
	long nr_opened = 0, nr_closed = 0, nr_total;
	bool reload_csum = false;
	struct path old_path;

	if (new_root) {
		int err = path_lookup(new_root, LOOKUP_FOLLOW |
				LOOKUP_DIRECTORY, &nd);
		if (err) {
			printk(KERN_ERR"PFCache: lookup \"%s\" failed %d\n",
					new_root, err);
			return err;
		}
		if (!test_opt2(sb, CSUM)) {
			set_opt2(sb, CSUM);
			reload_csum = true;
		}
	} else {
		nd.path.mnt = NULL;
		nd.path.dentry = NULL;
	}

	spin_lock(&EXT4_SB(sb)->s_pfcache_lock);
	old_path = EXT4_SB(sb)->s_pfcache_root;
	EXT4_SB(sb)->s_pfcache_root = nd.path;
	spin_unlock(&EXT4_SB(sb)->s_pfcache_lock);
	path_put(&old_path);

	spin_lock(&inode_lock);

	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		if (inode->i_state & (I_FREEING|I_CLEAR|I_WILL_FREE|I_NEW))
			continue;
		if (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode))
			continue;
		if (!ext4_test_inode_state(inode, EXT4_STATE_CSUM)) {
			if (!reload_csum)
				continue;
		} else if (!(EXT4_I(inode)->i_data_csum_end < 0))
			continue;
		__iget(inode);
		spin_unlock(&inode_lock);
		iput(old_inode);
		old_inode = inode;

		nd.path.mnt = NULL;
		nd.path.dentry = NULL;

		mutex_lock(&inode->i_mutex);

		if (!ext4_test_inode_state(inode, EXT4_STATE_CSUM)) {
			if (!reload_csum)
				goto next;
			if (S_ISDIR(inode->i_mode)) {
				ext4_load_dir_csum(inode);
				goto next;
			}
			if (ext4_load_data_csum(inode))
				goto next;
		} else if (!(EXT4_I(inode)->i_data_csum_end < 0) ||
				S_ISDIR(inode->i_mode))
			goto next;

		if (new_root) {
			const struct cred *cur_cred;
			int err;

			nd.flags = LOOKUP_STRICT;
			nd.last_type = LAST_ROOT;
			nd.depth = 0;
			nd.path = EXT4_SB(sb)->s_pfcache_root;
			path_get(&nd.path);

			pfcache_path(inode, path);
			cur_cred = override_creds(&init_cred);
			err = path_walk(path, &nd);
			revert_creds(cur_cred);
			if (err) {
				nd.path.mnt = NULL;
				nd.path.dentry = NULL;
			}
		}

		file = inode->i_peer_file;
		if ((!nd.path.mnt && !file) || (nd.path.mnt && file &&
		     file->f_mapping == nd.path.dentry->d_inode->i_mapping))
			goto next;

		if (file) {
			close_inode_peer(inode);
			nr_closed++;
		}

		if (nd.path.mnt) {
			path_get(&nd.path);
			if (!open_inode_peer(inode, &nd.path, &init_cred))
				nr_opened++;
		}
next:
		mutex_unlock(&inode->i_mutex);
		path_put(&nd.path);
		cond_resched();
		spin_lock(&inode_lock);
	}
	spin_unlock(&inode_lock);
	iput(old_inode);

	percpu_counter_add(&EXT4_SB(sb)->s_pfcache_peers,
			   nr_opened - nr_closed);
	nr_total = percpu_counter_sum(&EXT4_SB(sb)->s_pfcache_peers);

	if (new_root && (old_root || nr_total))
		printk(KERN_INFO"PFCache: relink %u:%u to \"%s\""
				" +%ld -%ld =%ld peers\n",
				MAJOR(sb->s_dev), MINOR(sb->s_dev), new_root,
				nr_opened, nr_closed, nr_total);
	if (!new_root && nr_total)
		printk(KERN_ERR"PFCache: %ld peers lost", nr_total);

	return 0;
}

#define MAX_LOCK_BATCH	256

long ext4_dump_pfcache(struct super_block *sb,
		      struct pfcache_dump_request __user *user_req)
{
	struct inode *inode, *old_inode = NULL;
	struct pfcache_dump_request req;
	u8 __user *user_buffer;
	u64 state, *x;
	void *buffer, *p;
	long ret, size;
	int lock_batch = 0;

	if (copy_from_user(&req, user_req, sizeof(req)))
		return -EFAULT;

	if (!access_ok(VERIFY_WRITE, user_req,
		       req.header_size + req.buffer_size))
		return -EFAULT;

	/* check for unknown flags */
	if ((req.filter & ~PFCACHE_FILTER_MASK) ||
	    (req.payload & ~PFCACHE_PAYLOAD_MASK))
		return -EINVAL;

	buffer = kzalloc(PFCACHE_PAYLOAD_MAX_SIZE, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	ret = 0;
	/* skip all new fields in the user request header */
	user_buffer = (void*)user_req + req.header_size;

	spin_lock(&inode_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		if (inode->i_state & (I_FREEING|I_CLEAR|I_WILL_FREE|I_NEW))
			continue;
		if (!S_ISREG(inode->i_mode) ||
		    inode == EXT4_SB(sb)->s_balloon_ino)
			goto next;

		/* evaluate the inode state */
		state = 0;

		if (ext4_test_inode_state(inode, EXT4_STATE_CSUM) &&
		    EXT4_I(inode)->i_data_csum_end < 0)
			state |= PFCACHE_FILTER_WITH_CSUM;
		else
			state |= PFCACHE_FILTER_WITHOUT_CSUM;

		if (inode->i_peer_file)
			state |= PFCACHE_FILTER_WITH_PEER;
		else
			state |= PFCACHE_FILTER_WITHOUT_PEER;

		/* check state-filter */
		if (req.filter & state)
			goto next;

		/* check csum-filter */
		if ((req.filter & PFCACHE_FILTER_COMPARE_CSUM) &&
		    memcmp(EXT4_I(inode)->i_data_csum,
			    req.csum_filter, EXT4_DATA_CSUM_SIZE))
			goto next;

		/* -- add new filters above this line -- */

		/* check offset-filter at the last */
		if (req.offset > 0) {
			req.offset--;
			goto next;
		}

		/* construct the payload */
		p = buffer;

		if (req.payload & PFCACHE_PAYLOAD_CSUM) {
			BUILD_BUG_ON(PFCACHE_CSUM_SIZE != EXT4_DATA_CSUM_SIZE);
			if (state & PFCACHE_FILTER_WITH_CSUM)
				memcpy(p, EXT4_I(inode)->i_data_csum,
						EXT4_DATA_CSUM_SIZE);
			else
				memset(p, 0, EXT4_DATA_CSUM_SIZE);
			p += ALIGN(PFCACHE_CSUM_SIZE, sizeof(u64));
		}

		if (req.payload & PFCACHE_PAYLOAD_FHANDLE) {
			int fh_ret = vfs_inode_fhandle(inode, p,
					PFCACHE_FHANDLE_MAX);
			if (fh_ret < 0) {
				ret = fh_ret;
				goto out;
			}
			p += ALIGN(fh_ret, sizeof(u64));
		}

		if (req.payload & PFCACHE_PAYLOAD_STATE) {
			x = p;
			*x = state;
			p += sizeof(u64);
		}

		if (req.payload & PFCACHE_PAYLOAD_FSIZE) {
			x = p;
			*x = i_size_read(inode);
			p += sizeof(u64);
		}

		if (req.payload & PFCACHE_PAYLOAD_PAGES) {
			x = p;
			*x = inode->i_mapping->nrpages;
			p += sizeof(u64);
		}

		/* -- add new payloads above this line -- */

		size = p - buffer;
		BUG_ON(!IS_ALIGNED(size, sizeof(u64)));
		BUG_ON(size > PFCACHE_PAYLOAD_MAX_SIZE);

		if (size > req.buffer_size)
			goto out;

		pagefault_disable();
		if (!__copy_to_user_inatomic(user_buffer, buffer, size)) {
			pagefault_enable();
		} else {
			pagefault_enable();
			__iget(inode);
			spin_unlock(&inode_lock);
			iput(old_inode);
			old_inode = inode;
			if (copy_to_user(user_buffer, buffer, size)) {
				ret = -EFAULT;
				goto out_nolock;
			}
			cond_resched();
			lock_batch = 0;
			spin_lock(&inode_lock);
		}

		ret++;
		user_buffer += size;
		req.buffer_size -= size;
next:
		if (signal_pending(current)) {
			if (!ret)
				ret = -EINTR;
			goto out;
		}
		if (++lock_batch > MAX_LOCK_BATCH || need_resched() ||
				spin_needbreak(&inode_lock)) {
			__iget(inode);
			spin_unlock(&inode_lock);
			iput(old_inode);
			old_inode = inode;
			cond_resched();
			lock_batch = 0;
			spin_lock(&inode_lock);
		}
	}
out:
	spin_unlock(&inode_lock);
out_nolock:
	iput(old_inode);

	kfree(buffer);

	return ret;
}

static void ext4_init_data_csum(struct inode *inode)
{
	EXT4_I(inode)->i_data_csum_end = 0;
	sha_init((__u32 *)EXT4_I(inode)->i_data_csum);
	ext4_set_inode_state(inode, EXT4_STATE_CSUM);
	percpu_counter_inc(&EXT4_SB(inode->i_sb)->s_csum_partial);
}

void ext4_clear_data_csum(struct inode *inode)
{
	ext4_clear_inode_state(inode, EXT4_STATE_CSUM);
	if (!S_ISREG(inode->i_mode))
		return;
	if (EXT4_I(inode)->i_data_csum_end < 0)
		percpu_counter_dec(&EXT4_SB(inode->i_sb)->s_csum_complete);
	else
		percpu_counter_dec(&EXT4_SB(inode->i_sb)->s_csum_partial);
}

void ext4_start_data_csum(struct inode *inode)
{
	if (!ext4_test_inode_state(inode, EXT4_STATE_CSUM)) {
		spin_lock(&inode->i_lock);
		if (!ext4_test_inode_state(inode, EXT4_STATE_CSUM))
			ext4_init_data_csum(inode);
		spin_unlock(&inode->i_lock);
	}
	trace_ext4_start_data_csum(inode, inode->i_size);
}

int ext4_load_data_csum(struct inode *inode)
{
	int ret;

	ret = ext4_xattr_get(inode, EXT4_XATTR_INDEX_TRUSTED,
			EXT4_DATA_CSUM_NAME, EXT4_I(inode)->i_data_csum,
			EXT4_DATA_CSUM_SIZE);
	if (ret < 0)
		return ret;
	if (ret != EXT4_DATA_CSUM_SIZE)
		return -EIO;

	EXT4_I(inode)->i_data_csum_end = -1;
	ext4_set_inode_state(inode, EXT4_STATE_CSUM);
	percpu_counter_inc(&EXT4_SB(inode->i_sb)->s_csum_complete);
	return 0;
}

static int ext4_save_data_csum(struct inode *inode, u8 *csum)
{
	int ret;

	if (ext4_test_inode_state(inode, EXT4_STATE_CSUM) &&
	    EXT4_I(inode)->i_data_csum_end < 0 &&
	    memcmp(EXT4_I(inode)->i_data_csum, csum, EXT4_DATA_CSUM_SIZE))
		ext4_close_pfcache(inode);

	spin_lock(&inode->i_lock);
	if (ext4_test_inode_state(inode, EXT4_STATE_CSUM))
		ext4_clear_data_csum(inode);
	memcpy(EXT4_I(inode)->i_data_csum, csum, EXT4_DATA_CSUM_SIZE);
	EXT4_I(inode)->i_data_csum_end = -1;
	ext4_set_inode_state(inode, EXT4_STATE_CSUM);
	percpu_counter_inc(&EXT4_SB(inode->i_sb)->s_csum_complete);
	spin_unlock(&inode->i_lock);
	trace_ext4_save_data_csum(inode, inode->i_size);

	ext4_open_pfcache(inode);

	/* In order to guarantie csum consistenty force block allocation first */
	ret = ext4_alloc_da_blocks(inode);
	if (ret)
		return ret;

	return ext4_xattr_set(inode, EXT4_XATTR_INDEX_TRUSTED,
			EXT4_DATA_CSUM_NAME, EXT4_I(inode)->i_data_csum,
			EXT4_DATA_CSUM_SIZE, 0);
}

void ext4_load_dir_csum(struct inode *inode)
{
	char value[EXT4_DIR_CSUM_VALUE_LEN];
	int ret;

	ret = ext4_xattr_get(inode, EXT4_XATTR_INDEX_TRUSTED,
			     EXT4_DATA_CSUM_NAME, value, sizeof(value));
	if (ret == EXT4_DIR_CSUM_VALUE_LEN &&
	    !strncmp(value, EXT4_DIR_CSUM_VALUE, sizeof(value)))
		ext4_set_inode_state(inode, EXT4_STATE_CSUM);
}

void ext4_save_dir_csum(struct inode *inode)
{
	ext4_set_inode_state(inode, EXT4_STATE_CSUM);
	ext4_xattr_set(inode, EXT4_XATTR_INDEX_TRUSTED,
			EXT4_DATA_CSUM_NAME,
			EXT4_DIR_CSUM_VALUE,
			EXT4_DIR_CSUM_VALUE_LEN, 0);
}

int ext4_truncate_data_csum(struct inode *inode, loff_t pos)
{
	int ret = 0;

	if (!S_ISREG(inode->i_mode))
		return 0;

	trace_ext4_truncate_data_csum(inode, pos);

	if (EXT4_I(inode)->i_data_csum_end < 0) {
		ext4_xattr_set(inode, EXT4_XATTR_INDEX_TRUSTED,
				EXT4_DATA_CSUM_NAME, NULL, 0, 0);
		ext4_close_pfcache(inode);
	}

	if (EXT4_I(inode)->i_data_csum_end < 0 ||
	    EXT4_I(inode)->i_data_csum_end > pos) {
		spin_lock(&inode->i_lock);
		ext4_clear_data_csum(inode);
		if (!pos && test_opt2(inode->i_sb, CSUM))
			ext4_init_data_csum(inode);
		else
			ret = -1;
		spin_unlock(&inode->i_lock);
	}
	return ret;
}

void ext4_update_data_csum(struct inode *inode, loff_t pos,
			   unsigned len, struct page* page)
{
	__u32 *digest = (__u32 *)EXT4_I(inode)->i_data_csum;
	const u8 *kaddr, *data;

	len += pos & (SHA_MESSAGE_BYTES-1);
	len &= ~(SHA_MESSAGE_BYTES-1);
	pos &= ~(loff_t)(SHA_MESSAGE_BYTES-1);

	if ((pos != EXT4_I(inode)->i_data_csum_end &&
	     ext4_truncate_data_csum(inode, pos)) || !len)
		return;

	EXT4_I(inode)->i_data_csum_end += len;

	kaddr = kmap_atomic(page, KM_USER0);
	data = kaddr + (pos & (PAGE_CACHE_SIZE - 1));
	sha_batch_transform(digest, data, len / SHA_MESSAGE_BYTES);
	kunmap_atomic(kaddr, KM_USER0);

	trace_ext4_update_data_csum(inode, pos);
}

static int ext4_finish_data_csum(struct inode *inode, u8 *csum)
{
	__u32 *digest = (__u32 *)csum;
	__u8 data[SHA_MESSAGE_BYTES * 2];
	loff_t end;
	unsigned tail;
	__be64 bits;

	BUILD_BUG_ON(EXT4_DATA_CSUM_SIZE != SHA_DIGEST_WORDS * 4);

	memcpy(csum, EXT4_I(inode)->i_data_csum, EXT4_DATA_CSUM_SIZE);

	end = EXT4_I(inode)->i_data_csum_end;
	if (end < 0)
		return 0;

	tail = inode->i_size - end;
	if (tail >= SHA_MESSAGE_BYTES)
		return -EIO;

	if (tail) {
		struct page *page;
		const u8 *kaddr;

		page = read_cache_page_gfp(inode->i_mapping,
					   end >> PAGE_CACHE_SHIFT,
					   GFP_NOFS);
		if (IS_ERR(page))
			return PTR_ERR(page);

		kaddr = kmap_atomic(page, KM_USER0);
		memcpy(data, kaddr + (end & (PAGE_CACHE_SIZE-1)), tail);
		kunmap_atomic(kaddr, KM_USER0);
		page_cache_release(page);
	}

	memset(data + tail, 0, sizeof(data) - tail);
	data[tail] = 0x80;

	bits = cpu_to_be64((end + tail) << 3);
	if (tail >= SHA_MESSAGE_BYTES - sizeof(bits)) {
		memcpy(data + SHA_MESSAGE_BYTES * 2 - sizeof(bits),
				&bits, sizeof(bits));
		sha_batch_transform(digest, data, 2);
	} else {
		memcpy(data + SHA_MESSAGE_BYTES - sizeof(bits),
				&bits, sizeof(bits));
		sha_batch_transform(digest, data, 1);
	}

	for (tail = 0; tail < SHA_DIGEST_WORDS ; tail++)
		digest[tail] = cpu_to_be32(digest[tail]);

	return 0;
}

void ext4_commit_data_csum(struct inode *inode)
{
	u8 csum[EXT4_DATA_CSUM_SIZE];

	if (!S_ISREG(inode->i_mode) || EXT4_I(inode)->i_data_csum_end < 0)
		return;

	mutex_lock(&inode->i_mutex);
	if (ext4_test_inode_state(inode, EXT4_STATE_CSUM) &&
	    !ext4_finish_data_csum(inode, csum))
		ext4_save_data_csum(inode, csum);
	else
		ext4_truncate_data_csum(inode, 0);
	mutex_unlock(&inode->i_mutex);
}

static int ext4_xattr_trusted_csum_get(struct inode *inode, const char *name,
				       void *buffer, size_t size)
{
	u8 csum[EXT4_DATA_CSUM_SIZE];
	int i;

	if (strcmp(name, ""))
		return -ENODATA;

	if (!test_opt2(inode->i_sb, CSUM))
		return -EOPNOTSUPP;

	if (S_ISDIR(inode->i_mode))
		return ext4_xattr_get(inode, EXT4_XATTR_INDEX_TRUSTED,
				      EXT4_DATA_CSUM_NAME, buffer, size);

	if (!S_ISREG(inode->i_mode))
		return -ENODATA;

	if (!buffer)
		return EXT4_DATA_CSUM_SIZE * 2;

	spin_lock(&inode->i_lock);
	if (ext4_test_inode_state(inode, EXT4_STATE_CSUM) &&
	    EXT4_I(inode)->i_data_csum_end < 0) {
		memcpy(csum, EXT4_I(inode)->i_data_csum, EXT4_DATA_CSUM_SIZE);
	} else {
		spin_unlock(&inode->i_lock);
		return -ENODATA;
	}
	spin_unlock(&inode->i_lock);

	if (size == EXT4_DATA_CSUM_SIZE) {
		memcpy(buffer, csum, EXT4_DATA_CSUM_SIZE);
		return EXT4_DATA_CSUM_SIZE;
	}

	if (size >= EXT4_DATA_CSUM_SIZE * 2) {
		for ( i = 0 ; i < EXT4_DATA_CSUM_SIZE ; i++ )
			buffer = pack_hex_byte(buffer, csum[i]);
		return EXT4_DATA_CSUM_SIZE * 2;
	}

	return -ERANGE;
}

static int ext4_xattr_trusted_csum_set(struct inode *inode, const char *name,
				const void *value, size_t size, int flags)
{
	const char *text = value;
	u8 csum[EXT4_DATA_CSUM_SIZE];
	int i;

	if (strcmp(name, ""))
		return -ENODATA;

	if (!test_opt2(inode->i_sb, CSUM))
		return -EOPNOTSUPP;

	if (S_ISDIR(inode->i_mode)) {
		if (!value)
			ext4_clear_inode_state(inode, EXT4_STATE_CSUM);
		else if (size == EXT4_DIR_CSUM_VALUE_LEN &&
			 !strncmp(value, EXT4_DIR_CSUM_VALUE, size))
			ext4_set_inode_state(inode, EXT4_STATE_CSUM);
		else
			return -EINVAL;

		return ext4_xattr_set(inode, EXT4_XATTR_INDEX_TRUSTED,
				      EXT4_DATA_CSUM_NAME, value, size, flags);
	}

	if (!S_ISREG(inode->i_mode))
		return -ENODATA;

	if (ext4_test_inode_state(inode, EXT4_STATE_CSUM)) {
		if (flags & XATTR_CREATE)
			return -EEXIST;
	} else {
		if (flags & XATTR_REPLACE)
			return -ENODATA;
	}

	if (!value) {
		ext4_truncate_data_csum(inode, 1);
		return 0;
	}

	if (size == EXT4_DATA_CSUM_SIZE) {
		memcpy(csum, value, EXT4_DATA_CSUM_SIZE);
	} else if (size == EXT4_DATA_CSUM_SIZE * 2) {
		for ( i = 0 ; i < EXT4_DATA_CSUM_SIZE ; i++ ) {
			int hi = hex_to_bin(text[i*2]);
			int lo = hex_to_bin(text[i*2+1]);
			if ((hi < 0) || (lo < 0))
				return -EINVAL;
			csum[i] = (hi << 4) | lo;
		}
	} else
		return -EINVAL;

	if (mapping_writably_mapped(inode->i_mapping))
		return -EBUSY;

	return ext4_save_data_csum(inode, csum);
}

#define XATTR_TRUSTED_CSUM_PREFIX XATTR_TRUSTED_PREFIX EXT4_DATA_CSUM_NAME
#define XATTR_TRUSTED_CSUM_PREFIX_LEN (sizeof (XATTR_TRUSTED_CSUM_PREFIX) - 1)

static size_t
ext4_xattr_trusted_csum_list(struct inode *inode, char *list, size_t list_size,
			     const char *name, size_t name_len)
{
	return 0;
}

struct xattr_handler ext4_xattr_trusted_csum_handler = {
	.prefix = XATTR_TRUSTED_CSUM_PREFIX,
	.list   = ext4_xattr_trusted_csum_list,
	.get    = ext4_xattr_trusted_csum_get,
	.set    = ext4_xattr_trusted_csum_set,
};
