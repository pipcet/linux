// SPDX-License-Identifier: GPL-2.0+
/*
 * Management (EP0) driver for Apple M1 mailbox-based IOP communication.
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

#define TIMEOUT_MSEC	      800

struct apple_mbox_msg {
	u64 payload;
	u64 endpoint;
};

struct apple_mgmt {
	struct device *dev;
	struct rproc *rproc;
	struct mbox_client cl;
	struct mbox_chan *chan;
};

#define EP0_TYPE_MASK     (0xfffULL << 52)
#define EP0_TYPE_HELLO    (0x001ULL << 52)
#define EP0_TYPE_EHLLO    (0x002ULL << 52)
#define EP0_TYPE_START    (0x005ULL << 52)
#define EP0_TYPE_RESET    (0x006ULL << 52)
#define EP0_TYPE_EPMAP    (0x008ULL << 52)
#define EP0_TYPE_PWROK    (0x007ULL << 52)
#define EP0_TYPE_PWRACK   (0x00bULL << 52)

#define EP0_START (EP0_TYPE_START | 0x0002)
#define EP0_EHLLO (EP0_TYPE_EHLLO | 0x0001)
#define EP0_RESET (EP0_TYPE_RESET | 0x0220)

#define EP0_EPMAP_LAST    (0x8ULL << 48)
#define EP0_EPMAP_PAGE(p) (((p) >> 32) & 0x7ULL)


static void apple_mgmt_receive_data(struct mbox_client *cl, void *ptr)
{
	struct apple_mgmt *mgmt = container_of(cl, struct apple_mgmt, cl);
	struct apple_mbox_msg *msg = ptr;

	if ((msg->payload & EP0_TYPE_MASK) == EP0_TYPE_PWROK) {
		struct apple_mbox_msg response;
		response.payload = msg->payload;
		response.endpoint = msg->endpoint;
		response.payload &= ~EP0_TYPE_MASK;
		response.payload |= EP0_TYPE_PWRACK;
		mbox_send_message(mgmt->chan, &response);
		return;
	}

	if ((msg->payload & EP0_TYPE_MASK) == EP0_TYPE_PWRACK) {
		/* We're good to go */
		return;
	}

	dev_err(mgmt->dev, "unexpected message received on EP0: %016llx\n",
		msg->payload);

	/* should we crash rproc here? I think we should! */
}

static int apple_mgmt_probe(struct platform_device *pdev)
{
	int ret;
	struct apple_mgmt *mgmt;

	mgmt = devm_kzalloc(&pdev->dev, sizeof *mgmt, GFP_KERNEL);
	if (!mgmt)
		return -ENOMEM;

	mgmt->dev = &pdev->dev;
	mgmt->rproc =
		platform_get_drvdata(to_platform_device(pdev->dev.parent));
	mgmt->cl.dev = mgmt->dev;
	mgmt->cl.rx_callback = apple_mgmt_receive_data;
	mgmt->cl.tx_tout = TIMEOUT_MSEC;

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
