/*
 *  include/bc/vmpages.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __UB_PAGES_H_
#define __UB_PAGES_H_

#include <linux/linkage.h>
#include <linux/sched.h>	/* for get_exec_ub() */
#include <linux/mm.h>
#include <bc/beancounter.h>
#include <bc/decl.h>

extern int glob_ve_meminfo;

/*
 * Check whether vma has private or copy-on-write mapping.
 */
#define VM_UB_PRIVATE(__flags, __file)					\
		( ((__flags) & VM_WRITE) ?				\
			(__file) == NULL || !((__flags) & VM_SHARED) :	\
			0						\
		)

UB_DECLARE_FUNC(int, ub_memory_charge(struct mm_struct *mm,
			unsigned long size,
			unsigned vm_flags,
			struct file *vm_file,
			int strict))
UB_DECLARE_VOID_FUNC(ub_memory_uncharge(struct mm_struct *mm,
			unsigned long size,
			unsigned vm_flags,
			struct file *vm_file))

struct shmem_inode_info;
UB_DECLARE_FUNC(int, ub_shmpages_charge(struct shmem_inode_info *i,
			unsigned long sz))
UB_DECLARE_VOID_FUNC(ub_shmpages_uncharge(struct shmem_inode_info *i,
			unsigned long sz))
UB_DECLARE_VOID_FUNC(ub_tmpfs_respages_inc(struct shmem_inode_info *shi))
UB_DECLARE_VOID_FUNC(ub_tmpfs_respages_sub(struct shmem_inode_info *shi,
			unsigned long size))
#define ub_tmpfs_respages_dec(shi)	ub_tmpfs_respages_sub(shi, 1)

UB_DECLARE_FUNC(int, ub_locked_charge(struct mm_struct *mm,
			unsigned long size))
UB_DECLARE_VOID_FUNC(ub_locked_uncharge(struct mm_struct *mm,
			unsigned long size))
UB_DECLARE_FUNC(int, ub_lockedshm_charge(struct shmem_inode_info *shi,
			unsigned long size))
UB_DECLARE_VOID_FUNC(ub_lockedshm_uncharge(struct shmem_inode_info *shi,
			unsigned long size))

extern void __ub_update_oomguarpages(struct user_beancounter *ub);

static inline int ub_swap_full(struct user_beancounter *ub)
{
	return (ub->ub_parms[UB_SWAPPAGES].held * 2 >
			ub->ub_parms[UB_SWAPPAGES].limit);
}

#ifdef CONFIG_BC_SWAP_ACCOUNTING
#define SWP_DECLARE_FUNC(ret, decl)	UB_DECLARE_FUNC(ret, decl)
#define SWP_DECLARE_VOID_FUNC(decl)	UB_DECLARE_VOID_FUNC(decl)
#else
#define SWP_DECLARE_FUNC(ret, decl)	static inline ret decl {return (ret)0;}
#define SWP_DECLARE_VOID_FUNC(decl)	static inline void decl { }
#endif

struct swap_info_struct;
SWP_DECLARE_FUNC(int, ub_swap_init(struct swap_info_struct *si, pgoff_t n))
SWP_DECLARE_VOID_FUNC(ub_swap_fini(struct swap_info_struct *si))
SWP_DECLARE_VOID_FUNC(ub_swapentry_inc(struct swap_info_struct *si, pgoff_t n,
			struct user_beancounter *ub))
SWP_DECLARE_VOID_FUNC(ub_swapentry_dec(struct swap_info_struct *si, pgoff_t n))
SWP_DECLARE_VOID_FUNC(ub_swapentry_unuse(struct swap_info_struct *si, pgoff_t n))

#ifdef CONFIG_BC_RSS_ACCOUNTING

int ub_try_to_free_pages(struct user_beancounter *ub, gfp_t gfp_mask);

extern int __ub_phys_charge(struct user_beancounter *ub,
		unsigned long pages, gfp_t gfp_mask);

static inline int ub_phys_charge(struct user_beancounter *ub,
		unsigned long pages, gfp_t gfp_mask)
{
	if (__try_charge_beancounter_percpu(ub, ub_percpu(ub, get_cpu()),
				UB_PHYSPAGES, pages)) {
		put_cpu();
		return __ub_phys_charge(ub, pages, gfp_mask);
	}
	put_cpu();
	return 0;
}

static inline void ub_phys_uncharge(struct user_beancounter *ub,
		unsigned long pages)
{
	uncharge_beancounter_fast(ub, UB_PHYSPAGES, pages);
}

int __ub_check_ram_limits(struct user_beancounter *ub, gfp_t gfp_mask, int size);

static inline int ub_check_ram_limits(struct user_beancounter *ub, gfp_t gfp_mask)
{
	if (likely(ub->ub_parms[UB_PHYSPAGES].limit == UB_MAXVALUE ||
			!precharge_beancounter(ub, UB_PHYSPAGES, 1)))
		return 0;

	return __ub_check_ram_limits(ub, gfp_mask, 1);
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE

static inline int ub_precharge_hpage(struct mm_struct *mm)
{
	struct user_beancounter *ub = mm_ub(mm);

	if (likely(ub->ub_parms[UB_PHYSPAGES].limit == UB_MAXVALUE ||
	    !precharge_beancounter(ub, UB_PHYSPAGES, HPAGE_PMD_NR)))
		return 0;

	return __ub_check_ram_limits(ub, GFP_TRANSHUGE, HPAGE_PMD_NR);
}

#endif

#else /* CONFIG_BC_RSS_ACCOUNTING */

static inline int ub_phys_charge(struct user_beancounter *ub,
		unsigned long pages, gfp_t gfp_mask)
{
	return charge_beancounter_fast(ub, UB_PHYSPAGES, pages, UB_FORCE);
}

static inline void ub_phys_uncharge(struct user_beancounter *ub,
		unsigned long pages)
{
	uncharge_beancounter_fast(ub, UB_PHYSPAGES, pages);
}

static inline int ub_check_ram_limits(struct user_beancounter *ub, gfp_t gfp_mask)
{
	return 0;
}

static inline int ub_precharge_hpage(struct mm_struct *mm)
{
	return 0;
}
#endif /* CONFIG_BC_RSS_ACCOUNTING */

void __show_ub_mem(struct user_beancounter *ub);
void show_ub_mem(struct user_beancounter *ub);

#endif /* __UB_PAGES_H_ */
