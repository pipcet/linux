// SPDX-License-Identifier: GPL-2.0+
/*
 * Endpoint driver for the panic endpoint of Apple M1 coprocessors.
 *
 * Copyright (C) 2021 Pip Cet <pipcet@gmail.com>
 */

#include <linux/apple-asc.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/mailbox_client.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/permalloc.h>
#include <linux/platform_device.h>
#include <linux/remoteproc.h>

struct apple_panic {
	struct device *dev;
	struct rproc *rproc;
	struct mbox_client cl;
	struct mbox_chan *chan;
	struct work_struct work;
	void *buf;
	dma_addr_t buf_iova;
	u64 payload;
	u64 endpoint;

	struct completion tx_complete;
};

static void apple_panic_tx_done(struct mbox_client *cl, void *msg, int code)
{
	struct apple_panic *panic = container_of(cl, struct apple_panic, cl);
	complete_all(&panic->tx_complete);
}

static void apple_panic_allocator_func(struct work_struct *work)
{
	struct apple_panic *panic = container_of(work, struct apple_panic,
						 work);
	struct apple_mbox_msg response;
	struct mbox_chan *chan;
	response.payload = panic->payload;
	response.endpoint = panic->endpoint;
#if 1
	panic->buf_iova = U36_MAX & panic->payload;
	if ((panic->buf_iova & 0xf00000000) == 0xf00000000) {
		/* Already mapped, and probably locked. Reuse the buffer. */
		printk("pa %016llx\n", 0xbe6194000 + panic->buf_iova - 0xf00000000);
		panic->buf = devm_memremap(panic->dev, 0xbe6194000 + panic->buf_iova - 0xf00000000, 0x4000, MEMREMAP_WB);
		response.payload &= ~U36_MAX;
		response.payload |= panic->buf_iova;
		printk("va %016llx\n", (u64)panic->buf);
	} else if (panic->buf_iova) {
		/* Already mapped, and probably locked. Reuse the buffer. */
		printk("pa %016llx\n", panic->buf_iova);
		if ((panic->buf_iova & 0xf00000000) == 0x200000000) {
			panic->buf = devm_ioremap_np(panic->dev, panic->buf_iova, 0x4000);
		} else {
			panic->buf = devm_memremap(panic->dev, panic->buf_iova, 0x4000, MEMREMAP_WB);
		}
		response.payload &= ~U36_MAX;
		response.payload |= panic->buf_iova;
		printk("va %016llx\n", (u64)panic->buf);
	} else {
		size_t buf_size = 0x10000;
		panic->buf = dma_alloc_coherent(panic->dev, buf_size,
						&panic->buf_iova, GFP_KERNEL);
		printk("allocating panic buf: %016llx / %016llx\n",
		       panic->buf, panic->buf_iova);
		permalloc_memory(panic->dev, panic->buf, buf_size);
		response.payload &= ~U36_MAX;
		response.payload |= panic->buf_iova;
	}
#endif
	response.endpoint = panic->endpoint;
	chan = apple_asc_lock_exclusively(panic->rproc);
	if (IS_ERR(chan))
		return;
	mbox_copy_and_send(chan, &response);
	apple_asc_unlock(panic->rproc, true);
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
	struct apple_panic *panic;
	int ret;
	u32 endpoint;

	panic = devm_kzalloc(&pdev->dev, sizeof *panic, GFP_KERNEL);
	if (!panic)
		return -ENOMEM;

	panic->dev = &pdev->dev;
	ret = dma_set_mask_and_coherent(panic->dev, DMA_BIT_MASK(64));
	if (ret < 0)
		return ret;

	panic->rproc = platform_get_drvdata(to_platform_device(pdev->dev.parent));
	panic->cl.dev = panic->dev;
	panic->cl.rx_callback = apple_panic_receive_data;
	panic->cl.tx_done = apple_panic_tx_done;
	panic->cl.tx_tout = ASC_TIMEOUT_MSEC;

	init_completion(&panic->tx_complete);
	ret = of_property_read_u32_index(panic->dev->of_node, "mboxes", 1,
					 &endpoint);
	if (ret < 0)
		return ret;

	panic->endpoint = endpoint;

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
