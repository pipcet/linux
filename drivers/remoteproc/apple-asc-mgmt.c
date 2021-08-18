// SPDX-License-Identifier: GPL-2.0+
/*
 * Management (EP0) driver for Apple M1 mailbox-based IOP communication.
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

struct apple_mgmt {
	struct device *dev;
	struct rproc *rproc;
	struct mbox_client cl;
	struct mbox_chan *chan;

	struct work_struct work;
	struct mutex mutex;
	struct completion c;

	u64 payload;
	u64 endpoint;
};

static void apple_mgmt_responder_func(struct work_struct *work)
{
	struct apple_mgmt *mgmt = container_of(work, struct apple_mgmt,
					       work);
	struct apple_mbox_msg response;
	struct mbox_chan *chan;

	chan = apple_asc_lock_exclusively(mgmt->rproc);

	response.payload = mgmt->payload;
	response.endpoint = mgmt->endpoint;
	response.payload &= ~EP0_TYPE_MASK;
	response.payload |= EP0_TYPE_PWRACK;
	mbox_copy_and_send(chan, &response);

	apple_asc_unlock(mgmt->rproc, true);
}

static void apple_mgmt_receive_data(struct mbox_client *cl, void *ptr)
{
	struct apple_mgmt *mgmt = container_of(cl, struct apple_mgmt, cl);
	struct apple_mbox_msg *msg = ptr;

	if ((msg->payload & EP0_TYPE_MASK) == EP0_TYPE_PWROK) {
		mgmt->payload = msg->payload;
		schedule_work(&mgmt->work);
	} else if ((msg->payload & EP0_TYPE_MASK) == EP0_TYPE_PWRACK) {
		complete_all(&mgmt->c);
		apple_asc_pwrack(mgmt->rproc);
	} else {
		dev_err(mgmt->dev, "unexpected message received on EP0: %016llx\n",
			msg->payload);

		/* should we crash rproc here? I think we should! */
	}
}

static int apple_mgmt_probe(struct platform_device *pdev)
{
	struct apple_mgmt *mgmt;

	mgmt = devm_kzalloc(&pdev->dev, sizeof *mgmt, GFP_KERNEL);
	if (!mgmt)
		return -ENOMEM;

	mgmt->dev = &pdev->dev;
	mgmt->rproc =
		platform_get_drvdata(to_platform_device(pdev->dev.parent));
	mgmt->cl.dev = mgmt->dev;
	mgmt->cl.rx_callback = apple_mgmt_receive_data;
	mgmt->cl.tx_tout = ASC_TIMEOUT_MSEC;

	init_completion(&mgmt->c);
	INIT_WORK(&mgmt->work, apple_mgmt_responder_func);
	mgmt->chan = mbox_request_channel(&mgmt->cl, 0);

	if (IS_ERR(mgmt->chan)) {
		dev_err(mgmt->dev, "couldn't acquire mailbox channel");
		return PTR_ERR(mgmt->chan);
	}

	return 0;
}

static const struct of_device_id apple_mgmt_of_match[] = {
	{ .compatible = "apple,apple-asc-mgmt" },
	{ },
};

static struct platform_driver apple_mgmt_platform_driver = {
	.driver = {
		.name = "apple-asc-mgmt",
		.of_match_table = apple_mgmt_of_match,
	},
	.probe = apple_mgmt_probe,
};

module_platform_driver(apple_mgmt_platform_driver);
MODULE_DESCRIPTION("Apple SoC Management Endpoint driver");
MODULE_LICENSE("GPL v2");
