/*
 * Pid namespaces
 *
 * Authors:
 *    (C) 2007 Pavel Emelyanov <xemul@openvz.org>, OpenVZ, SWsoft Inc.
 *    (C) 2007 Sukadev Bhattiprolu <sukadev@us.ibm.com>, IBM
 *     Many thanks to Oleg Nesterov for comments and help
 *
 */

#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/syscalls.h>
#include <linux/err.h>
#include <linux/acct.h>
#include <linux/module.h>
#include <linux/ve_proto.h>
#include <linux/kthread.h>

#include <bc/kmem.h>

#define BITS_PER_PAGE		(PAGE_SIZE*8)

struct pid_cache {
	int nr_ids;
	char name[16];
	struct kmem_cache *cachep;
	struct list_head list;
};

static LIST_HEAD(pid_caches_lh);
static DEFINE_MUTEX(pid_caches_mutex);
static struct kmem_cache *pid_ns_cachep;

/*
 * creates the kmem cache to allocate pids from.
 * @nr_ids: the number of numerical ids this pid will have to carry
 */

static struct kmem_cache *create_pid_cachep(int nr_ids)
{
	struct pid_cache *pcache;
	struct kmem_cache *cachep;

	mutex_lock(&pid_caches_mutex);
	list_for_each_entry(pcache, &pid_caches_lh, list)
		if (pcache->nr_ids == nr_ids)
			goto out;

	pcache = kmalloc(sizeof(struct pid_cache), GFP_KERNEL);
	if (pcache == NULL)
		goto err_alloc;

	snprintf(pcache->name, sizeof(pcache->name), "pid_%d", nr_ids);
	cachep = kmem_cache_create(pcache->name,
			sizeof(struct pid) + (nr_ids - 1) * sizeof(struct upid),
			0, SLAB_HWCACHE_ALIGN, NULL);
	if (cachep == NULL)
		goto err_cachep;

	pcache->nr_ids = nr_ids;
	pcache->cachep = cachep;
	list_add(&pcache->list, &pid_caches_lh);
out:
	mutex_unlock(&pid_caches_mutex);
	return pcache->cachep;

err_cachep:
	kfree(pcache);
err_alloc:
	mutex_unlock(&pid_caches_mutex);
	return NULL;
}

static struct pid_namespace *create_pid_namespace(struct pid_namespace *parent_pid_ns)
{
	struct pid_namespace *ns;
	unsigned int level = parent_pid_ns->level + 1;
	int i;

	ns = kmem_cache_zalloc(pid_ns_cachep, GFP_KERNEL);
	if (ns == NULL)
		goto out;

	ns->pidmap[0].page = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!ns->pidmap[0].page)
		goto out_free;

	ns->pid_cachep = create_pid_cachep(level + 1);
	if (ns->pid_cachep == NULL)
		goto out_free_map;

	kref_init(&ns->kref);
	ns->level = level;
	ns->parent = get_pid_ns(parent_pid_ns);
	ns->pid_max = PID_MAX_NS_DEFAULT;

	set_bit(0, ns->pidmap[0].page);
	atomic_set(&ns->pidmap[0].nr_free, BITS_PER_PAGE - 1);

	for (i = 1; i < PIDMAP_ENTRIES; i++)
		atomic_set(&ns->pidmap[i].nr_free, BITS_PER_PAGE);

	return ns;

out_free_map:
	kfree(ns->pidmap[0].page);
out_free:
	kmem_cache_free(pid_ns_cachep, ns);
out:
	return ERR_PTR(-ENOMEM);
}

static void destroy_pid_namespace(struct pid_namespace *ns)
{
	int i;

	for (i = 0; i < PIDMAP_ENTRIES; i++)
		kfree(ns->pidmap[i].page);

#ifdef CONFIG_BSD_PROCESS_ACCT
	kfree(ns->bacct);
#endif
	kmem_cache_free(pid_ns_cachep, ns);
}

struct pid_namespace *copy_pid_ns(unsigned long flags, struct pid_namespace *old_ns)
{
	if (!(flags & CLONE_NEWPID))
		return get_pid_ns(old_ns);
	if (flags & (CLONE_THREAD|CLONE_PARENT))
		return ERR_PTR(-EINVAL);
	return create_pid_namespace(old_ns);
}

void free_pid_ns(struct kref *kref)
{
	struct pid_namespace *ns, *parent;

	ns = container_of(kref, struct pid_namespace, kref);

	parent = ns->parent;
	destroy_pid_namespace(ns);

	if (parent != NULL)
		put_pid_ns(parent);
}

/*
 * this is a dirty ugly hack.
 */

static int __pid_ns_attach_task(struct pid_namespace *ns,
		struct task_struct *tsk, pid_t nr)
{
	struct pid *pid, *old_pid;
	enum pid_type type;
	unsigned long old_size, new_size;

	pid = kmem_cache_alloc(ns->pid_cachep, GFP_KERNEL);
	if (!pid)
		goto out;

	if (nr == 0)
		nr = alloc_pidmap(ns);
	else
		nr = set_pidmap(ns, nr);

	if (nr < 0)
		goto out_free;

	old_pid = task_pid(tsk);
	memcpy(pid, old_pid,
		sizeof(struct pid) + (ns->level - 1) * sizeof(struct upid));

	pid->level = ns->level;
	pid->numbers[pid->level].nr = nr;
	pid->numbers[pid->level].ns = get_pid_ns(ns);
	atomic_set(&pid->count, 1);
	for (type = 0; type < PIDTYPE_MAX; ++type)
		INIT_HLIST_HEAD(&pid->tasks[type]);

	old_size = kmem_cache_objuse(old_pid->numbers[old_pid->level].ns->pid_cachep);
	new_size = kmem_cache_objuse(pid->numbers[pid->level].ns->pid_cachep);
	/*
	 * Depending on sizeof(struct foo), cache flags (redzoning, etc)
	 * and actual CPU (cacheline_size() jump from 64 to 128 bytes after
	 * CPU detection) new size can very well be smaller than old size.
	 */
	if (new_size > old_size) {
		if (ub_kmem_charge(pid->ub, new_size - old_size, UB_HARD) < 0)
			goto out_enable;
	} else if (new_size < old_size)
		ub_kmem_uncharge(pid->ub, old_size - new_size);

	write_lock_irq(&tasklist_lock);

	change_pid(tsk, PIDTYPE_SID, pid);
	change_pid(tsk, PIDTYPE_PGID, pid);

	spin_lock(&pidmap_lock);
	tsk->signal->leader_pid = pid;
	put_pid(current->signal->tty_old_pgrp);
	current->signal->tty_old_pgrp = NULL;

	reattach_pid(tsk, pid);

	return 0;

out_enable:
	local_irq_enable();
	free_pidmap(pid->numbers + pid->level);
	put_pid_ns(ns);
out_free:
	kmem_cache_free(ns->pid_cachep, pid);
out:
	return -ENOMEM;
}

int pid_ns_attach_task(struct pid_namespace *ns, struct task_struct *tsk)
{
	return __pid_ns_attach_task(ns, tsk, 0);
}
EXPORT_SYMBOL_GPL(pid_ns_attach_task);

int pid_ns_attach_init(struct pid_namespace *ns, struct task_struct *tsk)
{
	int err;

	err = __pid_ns_attach_task(ns, tsk, 1);
	if (err < 0)
		return err;

	ns->child_reaper = tsk;
	return 0;
}
EXPORT_SYMBOL_GPL(pid_ns_attach_init);

#ifdef CONFIG_VE
static noinline void show_lost_task(struct task_struct *p)
{
	printk("Lost task: %d/%s/%p blocked: %lx pending: %lx\n",
			p->pid, p->comm, p,
			p->blocked.sig[0],
			p->pending.signal.sig[0]);
}

static void zap_ve_processes(struct ve_struct *env)
{
	int kthreads = 0;
	/* wait for all init childs exit */
	while (env->pcounter > 1 + kthreads) {
		struct task_struct *g, *p;
		long delay = 1;

		if (sys_wait4(-1, NULL, __WALL | WNOHANG, NULL) > 0)
			continue;
		/* it was ENOCHLD or no more children somehow */
		if (env->pcounter == 1)
			break;

		/* clear all signals to avoid wakeups */
		if (signal_pending(current))
			flush_signals(current);
		/* we have child without signal sent */
		__set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(delay);
		delay = (delay < HZ) ? (delay << 1) : HZ;
again:
		read_lock(&tasklist_lock);
		kthreads = 0;
		do_each_thread_ve(g, p) {
			if (p->flags & PF_KTHREAD) {
				kthreads++;
				continue;
			}
			if (p != current) {
				/*
				 * by that time no processes other then entered
				 * may exist in the VE. if some were missed by
				 * zap_pid_ns_processes() this was a BUG
				 */
				if (!p->did_ve_enter)
					show_lost_task(p);

				force_sig_specific(SIGKILL, p);

				if (reap_zombie(p))
					goto again;
			}
		} while_each_thread_ve(g, p);
		read_unlock(&tasklist_lock);
	}

	ve_hook_iterate_fini(VE_SS_CHAIN, get_exec_env());

	destroy_workqueue(env->khelper_wq);
	kthreadd_stop(env);
}
#endif

void zap_pid_ns_processes(struct pid_namespace *pid_ns)
{
	int nr;
	int rc;
	struct task_struct *task;
	struct ve_struct *env = get_exec_env();

	/*
	 * The last thread in the cgroup-init thread group is terminating.
	 * Find remaining pid_ts in the namespace, signal and wait for them
	 * to exit.
	 *
	 * Note:  This signals each threads in the namespace - even those that
	 * 	  belong to the same thread group, To avoid this, we would have
	 * 	  to walk the entire tasklist looking a processes in this
	 * 	  namespace, but that could be unnecessarily expensive if the
	 * 	  pid namespace has just a few processes. Or we need to
	 * 	  maintain a tasklist for each pid namespace.
	 *
	 */
	read_lock(&tasklist_lock);
	nr = next_pidmap(pid_ns, 1);
	while (nr > 0) {
		rcu_read_lock();

		/*
		 * Use force_sig() since it clears SIGNAL_UNKILLABLE ensuring
		 * any nested-container's init processes don't ignore the
		 * signal
		 */
		task = pid_task(find_vpid(nr), PIDTYPE_PID);
		if (task) {
			if ((task->flags & PF_KTHREAD))
				send_sig(SIGKILL, task, 1);
			else
				force_sig(SIGKILL, task);
		}

		rcu_read_unlock();

		nr = next_pidmap(pid_ns, nr);
	}
	read_unlock(&tasklist_lock);

	do {
		clear_thread_flag(TIF_SIGPENDING);
		rc = sys_wait4(-1, NULL, __WALL, NULL);
	} while (rc != -ECHILD);

	acct_exit_ns(pid_ns);

#ifdef CONFIG_VE
	if (pid_ns == env->ve_ns->pid_ns)
		zap_ve_processes(env);
#endif
	return;
}

static __init int pid_namespaces_init(void)
{
	pid_ns_cachep = KMEM_CACHE(pid_namespace, SLAB_PANIC);
	return 0;
}

__initcall(pid_namespaces_init);
