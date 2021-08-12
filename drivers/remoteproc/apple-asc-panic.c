// SPDX-License-Identifier: GPL-2.0+
/*
 * Endpoint driver for the panic endpoint of Apple M1 coprocessors.
 *
 * Copyright (C) 2021 Pip Cet <pipcet@gmail.com>
 */

#include <linux/mailbox_client.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/remoteproc.h>
#include <linux/io.h>
#include <linux/dma-mapping.h>

#ifndef U36_MAX
#define U36_MAX 0xfffffffffULL
#endif

#define TIMEOUT_MSEC	      800

struct apple_mbox_msg {
	u64 payload;
	u64 endpoint;
};

struct apple_panic {
	struct device *dev;
	struct rproc *rproc;
	struct mbox_client cl;
	struct mbox_chan *chan;
	struct work_struct work;
	void *buf;
	dma_addr_t buf_iova;
	u64 payload;
};

static void apple_panic_allocator_func(struct work_struct *work)
{
	struct apple_panic *panic = container_of(work, struct apple_panic,
						 work);
	struct apple_mbox_msg response;
	response.payload = panic->payload;
	response.endpoint = 0x01;
#if 1
	panic->buf_iova = U36_MAX & panic->payload;
	if ((panic->buf_iova & 0xf00000000) == 0xf00000000) {
		/* Already mapped, and probably locked. Reuse the buffer. */
		printk("pa %016llx\n", 0xbe6194000 + panic->buf_iova - 0xf00000000);
		panic->buf = devm_ioremap(panic->dev, 0xbe6194000 + panic->buf_iova - 0xf00000000, 0x4000);
		response.payload &= ~U36_MAX;
		response.payload |= panic->buf_iova;
		printk("va %016llx\n", panic->buf);
	} else {
		/* Already mapped, and probably locked. Reuse the buffer. */
		printk("pa %016llx\n", panic->buf_iova);
		panic->buf = devm_ioremap(panic->dev, panic->buf_iova, 0x4000);
		response.payload &= ~U36_MAX;
		response.payload |= panic->buf_iova;
		printk("va %016llx\n", panic->buf);
	}
#elif 1 /* temporary page table code */
	void *l1, *l2;
	u64 l2_iova;
	l1 = devm_ioremap(panic->dev, 0xbfff60000, 16384);
	dev_warn(panic->rproc->dev.parent, "allocating dma chunk");
	l2 = dma_alloc_coherent(panic->rproc->dev.parent, 16384, &l2_iova, GFP_KERNEL);
	printk("dma_alloc_coherent returned %p!\n",
	       l2);
	dev_warn(panic->rproc->dev.parent, "allocating dma chunk");
	panic->buf = dma_alloc_coherent(panic->rproc->dev.parent, 16384,
					&panic->buf_iova, GFP_KERNEL);
	panic->buf_iova = 0xf80000000;
	*(volatile u64 *)(l2 + 0) = panic->buf_iova | 3;
	*(volatile u64 *)(l1 + (0x40 << 3)) = l2_iova | 1;
	response.payload = (panic->payload & ~U36_MAX) + 0xf80000000;
#endif
	response.endpoint = 0x01;
	mbox_send_message(panic->chan, &response);
}

static void apple_panic_panic_func(struct work_struct *work)
{
	struct apple_panic *panic = container_of(work, struct apple_panic,
						 work);
	static char pbuf[2048];
	int i;
	for (i = 0; i < 2048; i++) {
		pbuf[i] = readb(panic->buf + i);
	}

	print_hex_dump(KERN_EMERG, "crash:", DUMP_PREFIX_NONE,
		       16, 1, pbuf, 128, true);
	rproc_report_crash(panic->rproc, RPROC_FATAL_ERROR);
}

static void apple_panic_receive_data(struct mbox_client *cl, void *msg)
{
	struct apple_panic *panic = container_of(cl, struct apple_panic, cl);
	struct apple_mbox_msg *mbox_msg = msg;

	if (panic->buf) {
		INIT_WORK(&panic->work, apple_panic_panic_func);
		schedule_work(&panic->work);
	} else {
		panic->payload = mbox_msg->payload;
		INIT_WORK(&panic->work, apple_panic_allocator_func);
		schedule_work(&panic->work);
	}
}

static int apple_panic_probe(struct platform_device *pdev)
{
	int ret;
	struct apple_panic *panic;

	panic = devm_kzalloc(&pdev->dev, sizeof *panic, GFP_KERNEL);
	if (!panic)
		return -ENOMEM;

	panic->dev = &pdev->dev;
	printk("device %016llx\n", &pdev->dev);
	printk("platform %016llx %016llx\n", &pdev->dev, platform_get_drvdata(pdev));
	printk("parent %016llx %016llx\n", &pdev->dev.parent, platform_get_drvdata(to_platform_device(pdev->dev.parent)));
	printk("gparent %016llx %016llx\n", &pdev->dev.parent->parent, platform_get_drvdata(to_platform_device(pdev->dev.parent->parent)));
	panic->rproc = platform_get_drvdata(to_platform_device(pdev->dev.parent));
	printk("found rproc %016llx\n", panic->rproc);
	panic->cl.dev = panic->dev;
	panic->cl.rx_callback = apple_panic_receive_data;
	panic->cl.tx_tout = TIMEOUT_MSEC;

	panic->chan = mbox_request_channel(&panic->cl, 0);

	if (IS_ERR(panic->chan)) {
		dev_err(panic->dev, "couldn't acquire mailbox channel");
		return PTR_ERR(panic->chan);
	}

	return 0;
}

static const struct of_device_id apple_panic_of_match[] = {
	{ .compatible = "apple,apple-asc-panic" },
	{ },
};

static struct platform_driver apple_panic_platform_driver = {
	.driver = {
		.name = "apple-asc-panic",
		.of_match_table = apple_panic_of_match,
	},
	.probe = apple_panic_probe,
};

module_platform_driver(apple_panic_platform_driver);
MODULE_DESCRIPTION("Apple SoC Panic Endpoint driver");
MODULE_LICENSE("GPL v2");
