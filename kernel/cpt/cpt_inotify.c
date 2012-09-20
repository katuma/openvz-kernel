/*
 *
 *  kernel/cpt/cpt_inotify.c
 *
 *  Copyright (C) 2000-2007  SWsoft
 *  All rights reserved.
 *
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/pipe_fs_i.h>
#include <linux/mman.h>
#include <linux/mnt_namespace.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/smp_lock.h>
#include <asm/uaccess.h>
#include <linux/vzcalluser.h>
#include <linux/inotify.h>
#include <linux/cpt_image.h>
#include <linux/fsnotify_backend.h>

#include "../../fs/notify/inotify/inotify.h"

#include <linux/cpt_obj.h>
#include <linux/cpt_context.h>
#include "cpt_mm.h"
#include "cpt_files.h"
#include "cpt_kernel.h"
#include "cpt_fsmagic.h"
#include "cpt_syscalls.h"

static int dump_watch_inode(struct path *path, cpt_context_t *ctx)
{
	int err;
	struct dentry *d;

	if (cpt_need_delayfs(path->mnt)) {
		eprintk_ctx("inotify migration for delayed mounts (NFS) is not "
				"supported\n");
		return -EINVAL;
	}

	d = path->dentry;
	if (IS_ROOT(d) || !d_unhashed(d))
		goto dump_dir;

	d = cpt_fake_link(d->d_inode->i_nlink ? d : NULL,
			path->mnt, d->d_inode, ctx);

	if (IS_ERR(d))
		return PTR_ERR(d);

dump_dir:
	err = cpt_dump_dir(d, path->mnt, ctx);
	if (d != path->dentry)
		dput(d);

	return err;
}

static int cpt_dump_watches(struct fsnotify_group *g, struct cpt_context *ctx)
{
	int err = 0;
	struct fsnotify_mark_entry *fse;
	struct inotify_inode_mark_entry *ie;
	struct cpt_inotify_wd_image wi;
	loff_t saved_obj;

	/* FIXME locking */
	list_for_each_entry(fse, &g->mark_entries, g_list) {
		struct path path;

		ie = container_of(fse, struct inotify_inode_mark_entry,
				fsn_entry);

		cpt_open_object(NULL, ctx);

		wi.cpt_next = CPT_NULL;
		wi.cpt_object = CPT_OBJ_INOTIFY_WATCH;
		wi.cpt_hdrlen = sizeof(wi);
		wi.cpt_content = CPT_CONTENT_ARRAY;
		wi.cpt_wd = ie->wd;
		wi.cpt_mask = fse->mask;

		ctx->write(&wi, sizeof(wi), ctx);

		cpt_push_object(&saved_obj, ctx);
		spin_lock(&fse->lock);
		if (ie->path.dentry == NULL) {
			err = -EINVAL;
			eprintk_ctx("inotify mark without path\n");
			spin_unlock(&fse->lock);
			break;
		}

		path = ie->path;
		path_get(&path);
		spin_unlock(&fse->lock);

		err = dump_watch_inode(&path, ctx);
		cpt_pop_object(&saved_obj, ctx);
		path_put(&path);

		if (err)
			break;

		cpt_close_object(ctx);
	}

	return err;
}

static int cpt_dump_events(struct fsnotify_group *g, struct cpt_context *ctx)
{
	/* FIXME - implement */
	if (!list_empty(&g->notification_list))
		wprintk_ctx("Inotify events are lost. Sorry...\n");

	return 0;
}

int cpt_dump_inotify(cpt_object_t *obj, cpt_context_t *ctx)
{
	int err;
	struct file *file = obj->o_obj;
	struct fsnotify_group *group;
	struct cpt_inotify_image ii;
	loff_t saved_obj;

	if (file->f_op != &inotify_fops) {
		eprintk_ctx("bad inotify file\n");
		return -EINVAL;
	}

	group = file->private_data;
	if (unlikely(group == NULL)) {
		eprintk_ctx("bad inotify group\n");
		return -EINVAL;
	}

	if (group->inotify_data.fa != NULL) {
		eprintk_ctx("inotify with fasync\n");
		return -ENOTSUPP;
	}

	cpt_open_object(NULL, ctx);

	ii.cpt_next = CPT_NULL;
	ii.cpt_object = CPT_OBJ_INOTIFY;
	ii.cpt_hdrlen = sizeof(ii);
	ii.cpt_content = CPT_CONTENT_ARRAY;
	ii.cpt_file = obj->o_pos;
	ii.cpt_user = group->inotify_data.user->uid;
	ii.cpt_max_events = group->max_events;
	ii.cpt_last_wd = group->max_events;

	ctx->write(&ii, sizeof(ii), ctx);
	cpt_push_object(&saved_obj, ctx);

	err = cpt_dump_watches(group, ctx);
	if (err == 0)
		err = cpt_dump_events(group, ctx);

	cpt_pop_object(&saved_obj, ctx);
	cpt_close_object(ctx);

	return err;
}
