/* SPDX-License-Identifier: (GPL-2.0 or BSD-3-Clause) */
/*
 * Copyright (C) 2020 Corellium LLC
 */

#include <linux/init.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/smp.h>
#include <linux/delay.h>
#include <linux/mm.h>

#include <asm/cpu_ops.h>
#include <asm/errno.h>
#include <asm/smp_plat.h>
#include <asm/io.h>

#define MAGIC_UNLOCK 0xc5acce55 /* See ARM CoreSightArchitecture Specification v3.0 ? */

struct cpu_apple_start_info {
    void __iomem *pmgr_start;
    u64 pmgr_start_size;
    void __iomem *cputrc_rvbar;
    void __iomem *dbg_unlock;
};

extern void apple_aic_cpu_prepare(unsigned int cpu);

static int cpu_apple_start0_unlocked = 0;
static DEFINE_PER_CPU(struct cpu_apple_start_info, cpu_apple_start_info);

static int __init cpu_apple_start_init(unsigned int cpu)
{
    return 0;
}

uint32_t real_entry[1024] __attribute__((aligned(65536))) = {
  0x58000141, /* counter sequence */
  0x100000a0,
  0xf9400001,
  0x91000421,
  0xf9000001,
  0x17fffffc,
  0x00000000,
  0x00000000,
  0x58000141,
  0x52a00200, /* reboot sequence */
  0xb9001420,
  0x52800000,
  0xb9001020,
  0x52800080,
  0xb9001c20,
  0x14000000,
  0x35200000,
  0x00000002,
  0x3d2b0000,
  0x00000002,
  0x10000401,
  0xf9400021,
  0xd61f0020,
  0x14000000, /* br . */ };

static int cpu_apple_start_prepare(unsigned int cpu)
{
    struct device_node *node;
    struct cpu_apple_start_info *info;

    info = per_cpu_ptr(&cpu_apple_start_info, cpu);

    if(info->pmgr_start && info->cputrc_rvbar && info->dbg_unlock)
        return 0;

    unsigned long addr = __pa_symbol(secondary_entry);
    unsigned long addr2 = __pa_symbol(real_entry);
    volatile uint32_t *p = real_entry;
    p++;
    int i = 0;
    for (i = 0; i < 64; i++) {
      *p++ = 0xd37ff800; /* x0 <<= 1 */
      if (((unsigned long) addr) & (1L << (63 - i))) {
	*p++ = 0xb2400000; /* x0 |= 1 */
      }
    }
    /* *p++ = 0xb2400000; x0 |= 1 */
    *p++ = 0xd61f0000; /* br x0 */
    *p++ = addr & 0xffffffff;
    *p++ = (addr >> 32);
    p = real_entry;
    *p++ = 0xd2800000; /* mov x0, #0 */

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

    //if(cpu)
    //    apple_aic_cpu_prepare(cpu);

    return 0;
}

static int cpu_apple_start_boot(unsigned int cpu)
{
    struct cpu_apple_start_info *info;
    unsigned long addr;

    if(!cpu_apple_start0_unlocked) {
        if(!cpu_apple_start_prepare(0)) {
            info = per_cpu_ptr(&cpu_apple_start_info, 0);
            writel(MAGIC_UNLOCK, info->dbg_unlock);
            cpu_apple_start0_unlocked = 1;
        } else
            pr_err("%s: failed to unlock boot CPU\n", __func__);
    }

    info = per_cpu_ptr(&cpu_apple_start_info, cpu);

    if(!info->pmgr_start || !info->cputrc_rvbar || !info->dbg_unlock)
        return -EINVAL;

    addr = __pa_symbol(secondary_entry);
    unsigned long addr2 = __pa_symbol(real_entry);
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

const struct cpu_operations cpu_apple_start_ops = {
    .name = "apple,startcpu",
    .cpu_init = cpu_apple_start_init,
    .cpu_prepare = cpu_apple_start_prepare,
    .cpu_boot = cpu_apple_start_boot,
};
