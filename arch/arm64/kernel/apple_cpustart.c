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

static void cpu_apple_wfi(void)
{
    /* can't do a proper WFI, because the CPU tends to lose state; will need
       a proper wrapper sequence */
    dsb(sy);
    wfe();
}

const struct cpu_operations cpu_apple_start_ops = {
    .name = "apple,startcpu",
    .cpu_wfi = cpu_apple_wfi,
};
