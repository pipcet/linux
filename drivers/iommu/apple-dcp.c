// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple DART (Device Address Resolution Table) IOMMU driver
 *
 * Copyright (C) 2021 The Asahi Linux Contributors
 *
 * Based on arm/arm-smmu/arm-ssmu.c and arm/arm-smmu-v3/arm-smmu-v3.c
 *  Copyright (C) 2013 ARM Limited
 *  Copyright (C) 2015 ARM Limited
 * and on exynos-iommu.c
 *  Copyright (c) 2011,2016 Samsung Electronics Co., Ltd.
 */

#include <linux/atomic.h>
#include <linux/bitfield.h>
#include <linux/clk.h>
#include <linux/cma.h>
#include <linux/dev_printk.h>
#include <linux/dma-iommu.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/io-pgtable.h>
#include <linux/iommu.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_iommu.h>
#include <linux/of_platform.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/swab.h>
#include <linux/types.h>

static int apple_dcp_probe(struct platform_device *pdev)
{
	struct resource *res;
	struct apple_dart *dart;
	struct device *dev = &pdev->dev;
	void *is_it_that_simple;
	dma_addr_t dmah;
	u64 size = 0x4000;

	do {
        	is_it_that_simple = dma_alloc_coherent(dev, size,
						       &dmah, GFP_KERNEL);
		size <<= 2;

		printk("is it that simple? %016lx+%016lx %016lx\n", is_it_that_simple, size, dmah);
	} while (is_it_that_simple);

	return -ENODEV;
}

static const struct of_device_id apple_dcp_of_match[] = {
	{ .compatible = "apple,t8103-dcp", .data = NULL },
	{},
};
MODULE_DEVICE_TABLE(of, apple_dcp_of_match);

static struct platform_driver apple_dcp_driver = {
	.driver	= {
		.name			= "apple-dcp",
		.of_match_table		= apple_dcp_of_match,
		.suppress_bind_attrs    = true,
	},
	.probe	= apple_dcp_probe,
};

module_platform_driver(apple_dcp_driver);

MODULE_LICENSE("GPL v2");
