#ifndef _LINUX_KTHREAD_H
#define _LINUX_KTHREAD_H
/* Simple interface for creating and stopping kernel threads without mess. */
#include <linux/err.h>
#include <linux/sched.h>

struct task_struct *kthread_create_ve(struct ve_struct *ve,
				   int (*threadfn)(void *data),
				   void *data,
				   const char namefmt[], ...)
	__attribute__((format(printf, 4, 5)));

#define kthread_create(threadfn, data, namefmt, ...)			\
({									\
	struct task_struct *__k						\
		= kthread_create_ve(get_ve0(), threadfn, data, namefmt,	\
				 ## __VA_ARGS__);			\
	__k;								\
})

/**
 * kthread_run - create and wake a thread.
 * @threadfn: the function to run until signal_pending(current).
 * @data: data ptr for @threadfn.
 * @namefmt: printf-style name for the thread.
 *
 * Description: Convenient wrapper for kthread_create() followed by
 * wake_up_process().  Returns the kthread or ERR_PTR(-ENOMEM).
 */
#define kthread_run(threadfn, data, namefmt, ...)			   \
({									   \
	struct task_struct *__k						   \
		= kthread_create(threadfn, data, namefmt, ## __VA_ARGS__); \
	if (!IS_ERR(__k))						   \
		wake_up_process(__k);					   \
	__k;								   \
})

/* Like kthread_run() but run a thread in VE context */
#define kthread_run_ve(ve, threadfn, data, namefmt, ...)		   \
({									   \
	struct task_struct *__k						   \
		= kthread_create_ve(ve, threadfn, data, namefmt,	   \
				    ## __VA_ARGS__);			   \
	if (!IS_ERR(__k))						   \
		wake_up_process(__k);					   \
	__k;								   \
})

void kthread_bind(struct task_struct *k, unsigned int cpu);
int kthread_stop(struct task_struct *k);
int kthread_should_stop(void);
int kthreadd_create(void);
void kthreadd_stop(struct ve_struct *ve);

int kthreadd(void *unused);
#ifdef CONFIG_VE
#define kthreadd_task get_exec_env()->_kthreadd_task
#else
extern struct task_struct *kthreadd_task;
#endif

#endif /* _LINUX_KTHREAD_H */
