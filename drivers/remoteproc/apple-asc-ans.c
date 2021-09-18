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

struct apple_ans_state {
	struct list_head list;
	size_t response_size;
	size_t response_off;
	size_t response_data_size;
};

struct apple_ans {
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

static void apple_ans_tx_done(struct mbox_client *cl, void *msg, int code)
{
	BUG_ON(1);
}

static void apple_ans_receive_data(struct mbox_client *cl, void *msg_header)
{
	struct apple_ans *ans = container_of(cl, struct apple_ans, cl);
	struct apple_mbox_msg *msg = msg_header;
	u64 payload = msg->payload;
	dev_err(ans->dev, "unexpected message %016llx\n", payload);
}

static int apple_ans_send_data(struct mbox_chan *chan, void *msg_header)
{
	BUG_ON(1);

	return 0;
}

static struct mbox_chan_ops apple_ans_mbox_chan_ops = {
	.send_data = apple_ans_send_data,
};

static int apple_ans_probe(struct platform_device *pdev)
{
	struct apple_ans *ans;
	u32 endpoint;
	int ret;

	ans = devm_kzalloc(&pdev->dev, sizeof *ans, GFP_KERNEL);
	if (!ans)
		return -ENOMEM;

	ans->dev = &pdev->dev;
	ans->rproc = platform_get_drvdata(to_platform_device(pdev->dev.parent));
	ans->cl.dev = ans->dev;
	ans->cl.rx_callback = apple_ans_receive_data;
	ans->cl.tx_done = apple_ans_tx_done;
	ans->cl.tx_tout = ASC_TIMEOUT_MSEC;

	ret = of_property_read_u32_index(ans->dev->of_node, "mboxes", 1,
					 &endpoint);
	if (ret < 0)
		return ret;

	ans->endpoint = endpoint;

	ans->chan = mbox_request_channel(&ans->cl, 0);

	if (IS_ERR(ans->chan)) {
		dev_err(ans->dev, "couldn't acquire mailbox channel\n");
		return PTR_ERR(ans->chan);
	}

	ans->downstream_chan.con_priv = ans;

	ans->mbox_controller.dev = ans->dev;
	ans->mbox_controller.ops = &apple_ans_mbox_chan_ops;
	ans->mbox_controller.chans = &ans->downstream_chan;
	ans->mbox_controller.num_chans = 1;
	ans->mbox_controller.txdone_irq = true;

	devm_mbox_controller_register(ans->dev, &ans->mbox_controller);

	return 0;
}

static const struct of_device_id apple_ans_of_match[] = {
	{ .compatible = "apple,apple-asc-ans" },
	{ },
};

static struct platform_driver apple_ans_platform_driver = {
	.driver = {
		.name = "apple-asc-ans",
		.of_match_table = apple_ans_of_match,
	},
	.probe = apple_ans_probe,
};

module_platform_driver(apple_ans_platform_driver);
MODULE_DESCRIPTION("Apple SoC ANS Endpoint driver");
MODULE_LICENSE("GPL v2");
