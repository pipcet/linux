/* SPDX-License-Identifier: (GPL-2.0 or BSD-3-Clause) */
/*
 * Copyright (C) 2020 Corellium LLC
 * Copyright (C) 2021 Pip Cet <pipcet@gmail.com>
 */

#include <linux/init.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/smp.h>
#include <linux/delay.h>
#include <linux/mm.h>
#include <linux/permalloc.h>

#include <asm/cpu_ops.h>
#include <asm/errno.h>
#include <asm/memory.h>
#include <asm/mmu.h>
#include <asm/mmu_context.h>
#include <asm/smp_plat.h>
#include <asm/io.h>

#include "cpu-reset.h"

#define MAGIC_UNLOCK 0xc5acce55 /* See ARM CoreSightArchitecture Specification v3.0 ? */

struct cpu_apple_start_info {
	void __iomem *pmgr_start;
	u64 pmgr_start_size;
	void __iomem *cputrc_rvbar;
	void __iomem *dbg_unlock;

	phys_addr_t *spin_table;
};

extern void apple_rvbar(void);
static phys_addr_t *spin_table;
static phys_addr_t spin_code;
static bool permalloced;

extern char apple_spin_code[];

static int cpu_apple_start0_unlocked = 0;
static DEFINE_PER_CPU(struct cpu_apple_start_info, cpu_apple_start_info);

static int __init cpu_apple_start_init(unsigned int cpu)
{
	return 0;
}

static int cpu_apple_start_prepare(unsigned int cpu)
{
	struct device_node *node;
	struct cpu_apple_start_info *info;

	info = per_cpu_ptr(&cpu_apple_start_info, cpu);

	if(info->pmgr_start && info->cputrc_rvbar && info->dbg_unlock)
		return 0;

	node = of_find_compatible_node(NULL, NULL, "spin-table");
	if (node) {
		resource_size_t spin_table_pa;
		of_get_address(node, 0, &spin_table_pa, NULL);
		if (!spin_table)
			spin_table = memremap(spin_table_pa, PAGE_SIZE, MEMREMAP_WC);
		info->spin_table = spin_table;
		return 0;
	}

	node = of_find_compatible_node(NULL, NULL, "apple,startcpu");
	if(!node) {
		pr_err("%s: missing startcpu node in device tree.\n", __func__);
		return -EINVAL;
	}

	if(!info->pmgr_start) {
		info->pmgr_start = of_iomap(node, cpu * 3);
		if(!info->pmgr_start) {
			pr_err("%s: failed to map start register for CPU %d.\n", __func__, cpu);
			return -EINVAL;
		}
		if(!of_get_address(node, cpu * 3, &info->pmgr_start_size, NULL))
			info->pmgr_start_size = 8;
	}

	if(!info->cputrc_rvbar) {
		info->cputrc_rvbar = of_iomap(node, cpu * 3 + 1);
		if(!info->cputrc_rvbar) {
			pr_err("%s: failed to map reset address register for CPU %d.\n", __func__, cpu);
			return -EINVAL;
		}
	}

	if(!info->dbg_unlock) {
		info->dbg_unlock = of_iomap(node, cpu * 3 + 2);
		if(!info->dbg_unlock) {
			pr_err("%s: failed to map unlock register for CPU %d.\n", __func__, cpu);
			return -EINVAL;
		}
	}

	return 0;
}

static int cpu_apple_start_boot(unsigned int cpu)
{
	struct cpu_apple_start_info *info;
	unsigned long addr, addr2;

	if(!cpu_apple_start0_unlocked) {
		if(!cpu_apple_start_prepare(0)) {
			info = per_cpu_ptr(&cpu_apple_start_info, 0);
			writel(MAGIC_UNLOCK, info->dbg_unlock);
			cpu_apple_start0_unlocked = 1;
		} else
			pr_err("%s: failed to unlock boot CPU\n", __func__);
	}

	info = per_cpu_ptr(&cpu_apple_start_info, cpu);

	if (info->spin_table) {
		info->spin_table[cpu] = __pa_symbol(secondary_entry);
		dsb(sy);
		sev();

		return 0;
	} else {
		if (!permalloced) {
			void *spin_code_va;
			permalloc_spin_table(__pa(spin_table = get_zeroed_page(GFP_KERNEL)));
			permalloced = true;
			spin_code = __pa(get_zeroed_page(GFP_KERNEL));
			permalloc_spin_code(spin_code);
			spin_code_va = memremap(spin_code, PAGE_SIZE, MEMREMAP_WB);
			if (spin_code_va)
				memcpy(spin_code_va, apple_spin_code, PAGE_SIZE);
			else
				printk("couldn't remap %016llx\n", spin_code);
		}
	}

	if(!info->pmgr_start || !info->cputrc_rvbar || !info->dbg_unlock)
		return -EINVAL;

	addr2 = __pa_symbol(apple_rvbar);
	dsb(sy);
	writeq(addr2, info->cputrc_rvbar);
	readq(info->cputrc_rvbar);
	writeq(addr2, info->cputrc_rvbar);
	writeq(addr2|1, info->cputrc_rvbar);
	readq(info->cputrc_rvbar);
	writeq(addr2|1, info->cputrc_rvbar);
	addr = readq(info->cputrc_rvbar) & 0xFFFFFFFFFul;
	dsb(sy);

	printk("initializing cpustart at %016llx to %016llx (= physaddr(%016llx))\n",
	       info->cputrc_rvbar, __pa_symbol(secondary_entry), secondary_entry);
	if(addr != addr2)
		pr_err("%s: CPU%d reset address: 0x%lx, failed to set to 0x%lx.\n", __func__, cpu, addr, addr2);

	writel(MAGIC_UNLOCK, info->dbg_unlock);

	writel(1 << cpu, info->pmgr_start);
	if(info->pmgr_start_size >= 12) {
		if(cpu < 4) {
			writel(1 << cpu, info->pmgr_start + 4);
			writel(0, info->pmgr_start + 8);
		} else {
			writel(0, info->pmgr_start + 4);
			writel(1 << (cpu - 4), info->pmgr_start + 8);
		}
	} else
		writel(1 << cpu, info->pmgr_start + 4);

	dsb(sy);
	sev();

	return 0;
}

#ifdef CONFIG_HOTPLUG_CPU
static bool cpu_apple_can_disable(unsigned int cpu)
{
	return true;
}

static int cpu_apple_disable(unsigned int cpu)
{
	struct cpu_apple_start_info *info;
	info = per_cpu_ptr(&cpu_apple_start_info, cpu);
	info->spin_table = spin_table;
	return 0;
}

static void cpu_apple_die(unsigned int cpu)
{
	cpu_soft_restart(spin_code, __pa(&spin_table[cpu]), 0, 0);
}

static int cpu_apple_kill(unsigned int cpu)
{
	return 0;
}
#endif

const struct cpu_operations cpu_apple_start_ops = {
	.name = "apple,startcpu",
	.cpu_init = cpu_apple_start_init,
	.cpu_prepare = cpu_apple_start_prepare,
	.cpu_boot = cpu_apple_start_boot,
#ifdef CONFIG_HOTPLUG_CPU
	.cpu_can_disable = cpu_apple_can_disable,
	.cpu_disable = cpu_apple_disable,
	.cpu_die = cpu_apple_die,
	.cpu_kill = cpu_apple_kill,
#endif
};
