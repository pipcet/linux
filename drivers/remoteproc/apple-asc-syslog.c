// SPDX-License-Identifier: GPL-2.0+
/*
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

struct apple_syslog {
	struct device *dev;
	struct rproc *rproc;
	struct mbox_client cl;
	struct mbox_chan *chan;
	struct work_struct work_allocator;
	struct work_struct work_message;
	struct completion c;
	void *buf;
	u64 buf_iova;
	u64 payload;
	u64 endpoint;
};

static void apple_syslog_allocator_func(struct work_struct *work)
{
	struct apple_syslog *syslog = container_of(work, struct apple_syslog,
						   work_allocator);
	struct apple_mbox_msg response;
	struct mbox_chan *chan;

	syslog->buf_iova = U36_MAX & syslog->payload;
	if (syslog->buf_iova)
		syslog->buf = devm_ioremap_np(syslog->dev, syslog->buf_iova,
					      0x4000);
	else
		syslog->buf =
			dma_alloc_coherent(syslog->rproc->dev.parent, 16384,
					   &syslog->buf_iova, GFP_KERNEL);
	response.payload = (syslog->payload &~ U36_MAX) | syslog->buf_iova;
	response.endpoint = syslog->endpoint;

	mbox_copy_and_send(syslog->chan, &response);
}

static void apple_syslog_message_func(struct work_struct *work)
{
	struct apple_syslog *syslog = container_of(work, struct apple_syslog,
						   work_message);
	static char pbuf[0x80];
	struct apple_mbox_msg response;
	int i;
	int page;

	response.payload = syslog->payload;
	page = syslog->payload & 0x1f;
	response.endpoint = syslog->endpoint;
	for (i = 0; i < 0x80; i++) {
		pbuf[i] = readb(syslog->buf + page * 0x80 + i);
	}

	print_hex_dump(KERN_EMERG, "message:", DUMP_PREFIX_NONE,
		       16, 1, pbuf, 128, true);

	//mbox_copy_and_send(syslog->chan, &response);
}

static void apple_syslog_tx_done(struct mbox_client *cl, void *msg, int code)
{
	struct apple_syslog *syslog = container_of(cl, struct apple_syslog,
						   cl);

	complete_all(&syslog->c);
}

static void apple_syslog_receive_data(struct mbox_client *cl, void *msg)
{
	struct apple_syslog *syslog = container_of(cl, struct apple_syslog, cl);
	struct apple_mbox_msg *mbox_msg = msg;

	syslog->payload = mbox_msg->payload;
	if ((syslog->payload & EP_TYPE_MASK) == EP_TYPE_BUFFER &&
	    syslog->buf == NULL) {
		schedule_work(&syslog->work_allocator);
	} else if (syslog->buf) {
		schedule_work(&syslog->work_message);
		mbox_copy_and_send(syslog->chan, msg);
	} else {
		printk(KERN_WARNING "ignoring early message\n");
		mbox_copy_and_send(syslog->chan, msg);
	}
}

static int apple_syslog_probe(struct platform_device *pdev)
{
	struct apple_syslog *syslog;
	u32 endpoint;
	int ret;

	syslog = devm_kzalloc(&pdev->dev, sizeof *syslog, GFP_KERNEL);
	if (!syslog)
		return -ENOMEM;

	syslog->dev = &pdev->dev;
	syslog->rproc = platform_get_drvdata(to_platform_device(pdev->dev.parent));
	//syslog->rproc = rproc_get_by_child(syslog->dev);
	syslog->cl.dev = syslog->dev;
	syslog->cl.rx_callback = apple_syslog_receive_data;
	syslog->cl.tx_done = apple_syslog_tx_done;
	syslog->cl.tx_tout = ASC_TIMEOUT_MSEC;

	ret = of_property_read_u32_index(syslog->dev->of_node, "mboxes", 1,
					 &endpoint);

	if (ret < 0)
		return ret;

	syslog->endpoint = endpoint;

	INIT_WORK(&syslog->work_allocator, apple_syslog_allocator_func);
	INIT_WORK(&syslog->work_message, apple_syslog_message_func);
	init_completion(&syslog->c);
	syslog->chan = mbox_request_channel(&syslog->cl, 0);

	if (IS_ERR(syslog->chan)) {
		dev_err(syslog->dev, "couldn't acquire mailbox channel");
		return PTR_ERR(syslog->chan);
	}

	return 0;
}

static const struct of_device_id apple_syslog_of_match[] = {
	{ .compatible = "apple,apple-asc-syslog" },
	{ },
};

static struct platform_driver apple_syslog_platform_driver = {
	.driver = {
		.name = "apple-asc-syslog",
		.of_match_table = apple_syslog_of_match,
	},
	.probe = apple_syslog_probe,
};

module_platform_driver(apple_syslog_platform_driver);
MODULE_DESCRIPTION("Apple SoC Syslog Endpoint driver");
MODULE_LICENSE("GPL v2");
