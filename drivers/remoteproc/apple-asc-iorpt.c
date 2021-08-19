// SPDX-License-Identifier: GPL-2.0+
/*
 * Endpoint driver for the ioreport endpoint of Apple M1 coprocessors.
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
#include <linux/platform_device.h>
#include <linux/remoteproc.h>

struct apple_queued_msg {
	struct list_head list;
	struct apple_mbox_msg msg;
};

struct apple_ioreport {
	struct device *dev;
	struct rproc *rproc;
	struct mbox_client cl;
	struct mbox_chan *chan;
	struct work_struct work;
	void *buf;
	dma_addr_t buf_iova;
	u64 endpoint;

	struct list_head queued_messages;

	struct completion tx_complete;
};

static void apple_ioreport_tx_done(struct mbox_client *cl, void *msg, int code)
{
	struct apple_ioreport *ioreport =
		container_of(cl, struct apple_ioreport, cl);
	complete_all(&ioreport->tx_complete);
}

static void apple_ioreport_allocator_func(struct work_struct *work)
{
	struct apple_ioreport *ioreport =
		container_of(work, struct apple_ioreport, work);
	struct apple_mbox_msg response;
	struct mbox_chan *chan;
	struct apple_queued_msg *qm;
	while (!list_empty(&ioreport->queued_messages)) {
		qm = list_first_entry(&ioreport->queued_messages,
				      struct apple_queued_msg, list);
		list_del(&qm->list);
		response.payload = qm->msg.payload;
		response.endpoint = ioreport->endpoint;
		if (!ioreport->buf) {
		response.payload = qm->msg.payload;
		response.endpoint = ioreport->endpoint;
#if 1
		ioreport->buf_iova = U36_MAX & qm->msg.payload;
		if ((ioreport->buf_iova & 0xf00000000) == 0xf00000000) {
			/* Already mapped, and probably locked. Reuse the buffer. */
			printk("pa %016llx\n", 0xbe6194000 + ioreport->buf_iova - 0xf00000000);
			ioreport->buf = devm_memremap(ioreport->dev, 0xbe6194000 + ioreport->buf_iova - 0xf00000000, 0x4000, MEMREMAP_WB);
			response.payload &= ~U36_MAX;
			response.payload |= ioreport->buf_iova;
			printk("va %016llx\n", (u64)ioreport->buf);
		} else if (ioreport->buf_iova) {
			/* Already mapped, and probably locked. Reuse the buffer. */
			printk("pa %016llx\n", ioreport->buf_iova);
			if ((ioreport->buf_iova & 0xf00000000) == 0x200000000) {
				ioreport->buf = devm_ioremap_np(ioreport->dev, ioreport->buf_iova, 0x4000);
			} else {
				ioreport->buf = devm_memremap(ioreport->dev, ioreport->buf_iova, 0x4000, MEMREMAP_WB);
			}
			response.payload &= ~U36_MAX;
			response.payload |= ioreport->buf_iova;
			printk("va %016llx\n", (u64)ioreport->buf);
		} else {
			size_t buf_size = 0x1000000;
			ioreport->buf = dma_alloc_coherent(ioreport->dev, buf_size,
							   &ioreport->buf_iova, GFP_KERNEL);
			printk("allocating ioreport buf: %016llx / %016llx\n",
			       ioreport->buf, ioreport->buf_iova);
			response.payload &= ~U36_MAX;
			response.payload |= ioreport->buf_iova;
		}
#endif
		}
		response.endpoint = ioreport->endpoint;
		mbox_copy_and_send(ioreport->chan, &response);
	}
}

static void apple_ioreport_ioreport_func(struct work_struct *work)
{
	struct apple_ioreport *ioreport = container_of(work, struct apple_ioreport,
						 work);
	static char pbuf[2048];
	int i;
	for (i = 0; i < 2048; i++) {
		pbuf[i] = readb(ioreport->buf + i);
	}

	print_hex_dump(KERN_EMERG, "IORPT:", DUMP_PREFIX_NONE,
		       16, 1, pbuf, 128, true);
	//rproc_report_crash(iorpt->rproc, RPROC_FATAL_ERROR);
}

static void apple_ioreport_receive_data(struct mbox_client *cl, void *msg)
{
	struct apple_ioreport *ioreport = container_of(cl, struct apple_ioreport, cl);
	struct apple_mbox_msg *mbox_msg = msg;
	struct apple_queued_msg *qm = devm_kzalloc(ioreport->dev, sizeof(*qm),
						   GFP_KERNEL);

	memcpy(&qm->msg, msg, sizeof(qm->msg));
	list_add(&qm->list, &ioreport->queued_messages);

	schedule_work(&ioreport->work);
	//mbox_copy_and_send(ioreport->chan, mbox_msg);
}

static int apple_ioreport_probe(struct platform_device *pdev)
{
	struct apple_ioreport *ioreport;
	int ret;
	u32 endpoint;

	ioreport = devm_kzalloc(&pdev->dev, sizeof *ioreport, GFP_KERNEL);
	if (!ioreport)
		return -ENOMEM;

	ioreport->dev = &pdev->dev;
	ret = dma_set_mask_and_coherent(ioreport->dev, DMA_BIT_MASK(64));
	if (ret < 0)
		return ret;

	ioreport->rproc = platform_get_drvdata(to_platform_device(pdev->dev.parent));
	ioreport->cl.dev = ioreport->dev;
	ioreport->cl.rx_callback = apple_ioreport_receive_data;
	ioreport->cl.tx_done = apple_ioreport_tx_done;
	ioreport->cl.tx_tout = ASC_TIMEOUT_MSEC;

	ret = of_property_read_u32_index(ioreport->dev->of_node, "mboxes", 1,
					 &endpoint);
	/* XXX */
	ioreport->endpoint = endpoint;

	ioreport->chan = mbox_request_channel(&ioreport->cl, 0);
	INIT_WORK(&ioreport->work, apple_ioreport_allocator_func);
	INIT_LIST_HEAD(&ioreport->queued_messages);

	if (IS_ERR(ioreport->chan)) {
		dev_err(ioreport->dev, "couldn't acquire mailbox channel");
		return PTR_ERR(ioreport->chan);
	}
	init_completion(&ioreport->tx_complete);

	return 0;
}

static const struct of_device_id apple_ioreport_of_match[] = {
	{ .compatible = "apple,apple-asc-iorpt" },
	{ },
};

static struct platform_driver apple_ioreport_platform_driver = {
	.driver = {
		.name = "apple-asc-ioreport",
		.of_match_table = apple_ioreport_of_match,
	},
	.probe = apple_ioreport_probe,
};

module_platform_driver(apple_ioreport_platform_driver);
MODULE_DESCRIPTION("Apple SoC I/O Report Endpoint driver");
MODULE_LICENSE("GPL v2");
