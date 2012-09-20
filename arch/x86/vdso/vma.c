/*
 * Set up the VMAs to tell the VM about the vDSO.
 * Copyright 2007 Andi Kleen, SUSE Labs.
 * Subject to the GPL, v.2
 */
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/random.h>
#include <linux/elf.h>
#include <asm/vsyscall.h>
#include <asm/vgtod.h>
#include <asm/proto.h>
#include <asm/vdso.h>

#include "vextern.h"		/* Just for VMAGIC.  */
#undef VEXTERN

unsigned int __read_mostly vdso_enabled = 1;

extern char vdso_start[], vdso_end[];
extern char vdso_rhel5_start[], vdso_rhel5_end[];
extern unsigned short vdso_sync_cpuid;

static struct page **vdso_pages;
static unsigned vdso_size;

static struct page **vdso_rhel5_pages;
static unsigned vdso_rhel5_size;

static inline void *var_ref(void *p, char *name)
{
	if (*(void **)p != (void *)VMAGIC) {
		printk("VDSO: variable %s broken\n", name);
		vdso_enabled = 0;
	}
	return p;
}

static int __init init_vdso_vars(void)
{
	int npages = (vdso_end - vdso_start + PAGE_SIZE - 1) / PAGE_SIZE;
	int i;
	char *vbase;

	vdso_size = npages << PAGE_SHIFT;
	vdso_pages = kmalloc(sizeof(struct page *) * npages, GFP_KERNEL);
	if (!vdso_pages)
		goto oom;
	for (i = 0; i < npages; i++) {
		struct page *p;
		p = alloc_page(GFP_KERNEL);
		if (!p)
			goto oom;
		vdso_pages[i] = p;
		copy_page(page_address(p), vdso_start + i*PAGE_SIZE);
	}

	vbase = vmap(vdso_pages, npages, 0, PAGE_KERNEL);
	if (!vbase)
		goto oom;

	if (memcmp(vbase, "\177ELF", 4)) {
		printk("VDSO: I'm broken; not ELF\n");
		vdso_enabled = 0;
	}

#define VEXTERN(x) \
	*(typeof(__ ## x) **) var_ref(VDSO64_SYMBOL(vbase, x), #x) = &__ ## x;
#include "vextern.h"
#undef VEXTERN
	return 0;

 oom:
	printk("Cannot allocate vdso\n");
	vdso_enabled = 0;
	return -ENOMEM;
}
__initcall(init_vdso_vars);

static int __init init_vdso_rhel5_vars(void)
{
	int npages = (vdso_rhel5_end - vdso_rhel5_start + PAGE_SIZE - 1) / PAGE_SIZE;
	int i;
	char *vbase;

	vdso_rhel5_size = npages << PAGE_SHIFT;
	vdso_rhel5_pages = kmalloc(sizeof(struct page *) * npages, GFP_KERNEL);
	if (!vdso_rhel5_pages)
		goto oom;
	for (i = 0; i < npages; i++) {
		struct page *p;
		p = alloc_page(GFP_KERNEL);
		if (!p)
			goto oom;
		vdso_rhel5_pages[i] = p;
		copy_page(page_address(p), vdso_rhel5_start + i*PAGE_SIZE);
	}

	vbase = vmap(vdso_rhel5_pages, npages, 0, PAGE_KERNEL);
	if (!vbase)
		goto oom;

	if (memcmp(vbase, "\177ELF", 4)) {
		printk("VDSO: I'm broken; not ELF\n");
		vdso_enabled = 0;
	}

#define VEXTERN(x) \
	*(typeof(__ ## x) **) var_ref(VDSO64_SYMBOL(vbase, rhel5_ ## x), #x) = &__ ## x;
#include "vextern.h"
#undef VEXTERN
	return 0;

 oom:
	printk("Cannot allocate vdso\n");
	vdso_enabled = 0;
	return -ENOMEM;
}
__initcall(init_vdso_rhel5_vars);

struct linux_binprm;

/* Put the vdso above the (randomized) stack with another randomized offset.
   This way there is no hole in the middle of address space.
   To save memory make sure it is still in the same PTE as the stack top.
   This doesn't give that many random bits */
static unsigned long vdso_addr(unsigned long start, unsigned len)
{
	unsigned long addr, end;
	unsigned offset;
	end = (start + PMD_SIZE - 1) & PMD_MASK;
	if (end >= TASK_SIZE_MAX)
		end = TASK_SIZE_MAX;
	end -= len;
	/* This loses some more bits than a modulo, but is cheaper */
	offset = get_random_int() & (PTRS_PER_PTE - 1);
	addr = start + (offset << PAGE_SHIFT);
	if (addr >= end)
		addr = end;

	/*
	 * page-align it here so that get_unmapped_area doesn't
	 * align it wrongfully again to the next page. addr can come in 4K
	 * unaligned here as a result of stack start randomization.
	 */
	addr = PAGE_ALIGN(addr);
	addr = align_addr(addr, NULL, ALIGN_VDSO);

	return addr;
}

/* Setup a VMA at program startup for the vsyscall page.
   Not called for compat tasks */
int __arch_setup_additional_pages(struct linux_binprm *bprm, int uses_interp,
				unsigned long map_address, struct page ** vdso_pages,
				unsigned vdso_size)
{
	struct mm_struct *mm = current->mm;
	unsigned long addr;
	int ret;

	if (!vdso_enabled && map_address == 0) {
		current->mm->context.vdso = NULL;
		return 0;
	}

	down_write(&mm->mmap_sem);
	if (map_address)
		addr = map_address;
	else
		addr = vdso_addr(mm->start_stack, vdso_size);
	addr = get_unmapped_area(NULL, addr, vdso_size, 0, 0);
	if (IS_ERR_VALUE(addr)) {
		ret = addr;
		goto up_fail;
	}

	current->mm->context.vdso = (void *)addr;

	ret = install_special_mapping(mm, addr, vdso_size,
				      VM_READ|VM_EXEC|
				      VM_MAYREAD|VM_MAYWRITE|VM_MAYEXEC|
				      VM_ALWAYSDUMP,
				      vdso_pages);
	if (ret) {
		current->mm->context.vdso = NULL;
		goto up_fail;
	}

up_fail:
	up_write(&mm->mmap_sem);
	return ret;
}

int arch_setup_additional_pages(struct linux_binprm *bprm, int uses_interp,
				unsigned long map_address)
{
	return __arch_setup_additional_pages(bprm, uses_interp, map_address,
							vdso_pages, vdso_size);
}
EXPORT_SYMBOL(arch_setup_additional_pages);

int arch_setup_additional_pages_rhel5(struct linux_binprm *bprm, int uses_interp,
				unsigned long map_address)
{
	return __arch_setup_additional_pages(bprm, uses_interp, map_address,
					vdso_rhel5_pages, vdso_rhel5_size);
}
EXPORT_SYMBOL(arch_setup_additional_pages_rhel5);

int vdso_is_rhel5(struct page *page)
{
	return page == vdso_rhel5_pages[0];
}
EXPORT_SYMBOL(vdso_is_rhel5);

static __init int vdso_setup(char *s)
{
	vdso_enabled = simple_strtoul(s, NULL, 0);
	return 0;
}
__setup("vdso=", vdso_setup);
