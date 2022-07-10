// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2021 Pip Cet <pipcet@gmail.com>
 */

#include <linux/apple-asc.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/list.h>
#include <linux/mailbox_client.h>
#include <linux/mailbox_controller.h>
#include <linux/memory.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/remoteproc.h>
#include <linux/slab.h>

struct apple_initonly_state {
	struct list_head list;
	size_t response_size;
	size_t response_off;
	size_t response_data_size;
};

struct apple_initonly {
	struct device *dev;
	struct rproc *rproc;
	/* Our upstream mailbox: infallibly sends data via the Apple mbox */
	struct mbox_client cl;
	struct mbox_chan *chan;
	/* Our downstream mailbox: fallibly receives data to be put in buffer */
	struct mbox_controller mbox_controller;
	struct mbox_chan downstream_chan;

	spinlock_t lock;
	u64 endpoint;
};

static void apple_initonly_tx_done(struct mbox_client *cl, void *msg, int code)
{
	BUG_ON(1);
}

static void apple_initonly_receive_data(struct mbox_client *cl, void *msg_header)
{
	struct apple_initonly *initonly = container_of(cl, struct apple_initonly, cl);
	struct apple_mbox_msg *msg = msg_header;
	u64 payload = msg->payload;
	dev_err(initonly->dev, "unexpected message %016llx\n", payload);
}

static int apple_initonly_send_data(struct mbox_chan *chan, void *msg_header)
{
	BUG_ON(1);

	return 0;
}

static struct mbox_chan_ops apple_initonly_mbox_chan_ops = {
	.send_data = apple_initonly_send_data,
};

static int apple_initonly_probe(struct platform_device *pdev)
{
	struct apple_initonly *initonly;
	u32 endpoint;
	int ret;

	initonly = devm_kzalloc(&pdev->dev, sizeof *initonly, GFP_KERNEL);
	if (!initonly)
		return -ENOMEM;

	initonly->dev = &pdev->dev;
	initonly->rproc = platform_get_drvdata(to_platform_device(pdev->dev.parent));
	initonly->cl.dev = initonly->dev;
	initonly->cl.rx_callback = apple_initonly_receive_data;
	initonly->cl.tx_done = apple_initonly_tx_done;
	initonly->cl.tx_tout = ASC_TIMEOUT_MSEC;

	ret = of_property_read_u32_index(initonly->dev->of_node, "mboxes", 1,
					 &endpoint);
	if (ret < 0)
		return ret;

	initonly->endpoint = endpoint;

	initonly->chan = mbox_request_channel(&initonly->cl, 0);

	if (IS_ERR(initonly->chan)) {
		dev_err(initonly->dev, "couldn't acquire mailbox channel\n");
		return PTR_ERR(initonly->chan);
	}

	initonly->downstream_chan.con_priv = initonly;

	initonly->mbox_controller.dev = initonly->dev;
	initonly->mbox_controller.ops = &apple_initonly_mbox_chan_ops;
	initonly->mbox_controller.chans = &initonly->downstream_chan;
	initonly->mbox_controller.num_chans = 1;
	initonly->mbox_controller.txdone_irq = true;

	devm_mbox_controller_register(initonly->dev, &initonly->mbox_controller);

	return 0;
}

static const struct of_device_id apple_initonly_of_match[] = {
	{ .compatible = "apple,apple-asc-initonly" },
	{ },
};

static struct platform_driver apple_initonly_platform_driver = {
	.driver = {
		.name = "apple-asc-initonly",
		.of_match_table = apple_initonly_of_match,
	},
	.probe = apple_initonly_probe,
};

module_platform_driver(apple_initonly_platform_driver);
MODULE_DESCRIPTION("Apple SoC init-only Endpoint driver");
MODULE_LICENSE("GPL v2");
