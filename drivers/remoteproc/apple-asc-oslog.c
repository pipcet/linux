// SPDX-License-Identifier: GPL-2.0+
/*
 * Endpoint driver for the "oslog" endpoint of Apple M1 coprocessors.
 *
 * That sounds promising for debugging, right? It's not: we know how
 * to start this endpoint, but that's about it. It does need to be
 * started for the DCP to work though.
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

struct apple_queued_msg {
	struct list_head list;
	struct apple_mbox_msg msg;
};

struct apple_oslog {
	struct device *dev;
	struct rproc *rproc;
	struct mbox_client cl;
	struct mbox_chan *chan;

	u32 endpoint;
};

static void apple_oslog_tx_done(struct mbox_client *cl, void *msg, int code)
{
	/* Tell me more. */
}

static void apple_oslog_receive_data(struct mbox_client *cl, void *msg)
{
}

static int apple_oslog_probe(struct platform_device *pdev)
{
	struct apple_oslog *oslog;
	int ret;
	u32 endpoint;

	oslog = devm_kzalloc(&pdev->dev, sizeof *oslog, GFP_KERNEL);
	if (!oslog)
		return -ENOMEM;

	oslog->dev = &pdev->dev;
	ret = dma_set_mask_and_coherent(oslog->dev, DMA_BIT_MASK(64));
	if (ret < 0)
		return ret;

	oslog->rproc = platform_get_drvdata(to_platform_device(pdev->dev.parent));
	oslog->cl.dev = oslog->dev;
	oslog->cl.rx_callback = apple_oslog_receive_data;
	oslog->cl.tx_done = apple_oslog_tx_done;
	oslog->cl.tx_tout = ASC_TIMEOUT_MSEC;

	ret = of_property_read_u32_index(oslog->dev->of_node, "mboxes", 1,
					 &endpoint);
	/* XXX */
	oslog->endpoint = endpoint;

	oslog->chan = mbox_request_channel(&oslog->cl, 0);

	if (IS_ERR(oslog->chan)) {
		dev_err(oslog->dev, "couldn't acquire mailbox channel\n");
		return PTR_ERR(oslog->chan);
	}

	struct apple_mbox_msg mbox;
	mbox.payload = 0x300000000000000;
	mbox.endpoint = 0x03;
	mbox_send_message(oslog->chan, &mbox);

	return 0;
}

static const struct of_device_id apple_oslog_of_match[] = {
	{ .compatible = "apple,apple-asc-oslog" },
	{ },
};

static struct platform_driver apple_oslog_platform_driver = {
	.driver = {
		.name = "apple-asc-oslog",
		.of_match_table = apple_oslog_of_match,
	},
	.probe = apple_oslog_probe,
};

module_platform_driver(apple_oslog_platform_driver);
MODULE_DESCRIPTION("Apple SoC oslog Endpoint driver");
MODULE_LICENSE("GPL v2");
