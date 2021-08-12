// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2021 Pip Cet <pipcet@gmail.com>
 */

#include <linux/io.h>
#include <linux/mailbox_client.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/remoteproc.h>
#include <linux/dma-mapping.h>

#ifndef U48_MAX
#define U48_MAX 0xffffffffffffULL
#endif

#ifndef U36_MAX
#define U36_MAX 0xfffffffffULL
#endif

#define TIMEOUT_MSEC	      800

struct apple_mbox_msg {
	u64 payload;
	u64 endpoint;
};

struct apple_syslog {
	struct device *dev;
	struct rproc *rproc;
	struct mbox_client cl;
	struct mbox_chan *chan;
	struct work_struct work;
	struct completion c;
	void *buf;
	u64 buf_iova;
	u64 payload;
};

static void apple_syslog_allocator_func(struct work_struct *work)
{
	struct apple_syslog *syslog = container_of(work, struct apple_syslog,
						   work);
	struct apple_mbox_msg response;

	syslog->buf_iova = U36_MAX & syslog->payload;
	if (syslog->buf_iova)
		syslog->buf = devm_ioremap(syslog->dev, syslog->buf_iova,
					   0x4000);
	else
		syslog->buf =
			dma_alloc_coherent(syslog->rproc->dev.parent, 16384,
					   &syslog->buf_iova, GFP_KERNEL);
	response.payload = (syslog->payload &~ U36_MAX) | syslog->buf_iova;
	response.endpoint = 2;

	reinit_completion(&syslog->c);
	mbox_send_message(syslog->chan, &response);
	wait_for_completion(&syslog->c);
}

static void apple_syslog_message_func(struct work_struct *work)
{
	struct apple_syslog *syslog = container_of(work, struct apple_syslog,
						   work);
	static char pbuf[2048];
	struct apple_mbox_msg response;
	int i;

	response.payload = syslog->payload;
	response.endpoint = 0x02;
	for (i = 0; i < 2048; i++) {
		pbuf[i] = readb(syslog->buf + i);
	}

	print_hex_dump(KERN_EMERG, "message:", DUMP_PREFIX_NONE,
		       16, 1, pbuf, 128, true);

	reinit_completion(&syslog->c);
	mbox_send_message(syslog->chan, &response);
	wait_for_completion(&syslog->c);
}

static void apple_syslog_tx_done(struct mbox_client *cl, void *msg, int code)
{
	struct apple_syslog *syslog = container_of(cl, struct apple_syslog,
						   cl);

	complete_all(&syslog->c);
}

#define EP_TYPE_MASK     (0xfffULL << 52)
#define EP_TYPE_BUFFER   (0x001ULL << 52)
#define EP_TYPE_EHLLO    (0x002ULL << 52)
#define EP_TYPE_MESSAGE  (0x003ULL << 52)
#define EP_TYPE_START    (0x005ULL << 52)
#define EP_TYPE_RESET    (0x006ULL << 52)
#define EP_TYPE_EPMAP    (0x008ULL << 52)
#define EP_TYPE_PWRACK   (0x00bULL << 52)

static void apple_syslog_receive_data(struct mbox_client *cl, void *msg)
{
	struct apple_syslog *syslog = container_of(cl, struct apple_syslog, cl);
	struct apple_mbox_msg *mbox_msg = msg;

	syslog->payload = mbox_msg->payload;
	if ((syslog->payload & EP_TYPE_MASK) == EP_TYPE_BUFFER &&
	    syslog->buf == NULL) {
		INIT_WORK(&syslog->work, apple_syslog_allocator_func);
		schedule_work(&syslog->work);
	} else if (syslog->buf) {
		INIT_WORK(&syslog->work, apple_syslog_message_func);
		schedule_work(&syslog->work);
	} else {
		printk(KERN_WARNING "ignoring early message\n");
		mbox_send_message(syslog->chan, msg);
	}
}

static int apple_syslog_probe(struct platform_device *pdev)
{
	int ret;
	struct apple_syslog *syslog;

	syslog = devm_kzalloc(&pdev->dev, sizeof *syslog, GFP_KERNEL);
	if (!syslog)
		return -ENOMEM;

	syslog->dev = &pdev->dev;
	syslog->rproc = rproc_get_by_child(syslog->dev);
	syslog->cl.dev = syslog->dev;
	syslog->cl.rx_callback = apple_syslog_receive_data;
	syslog->cl.tx_done = apple_syslog_tx_done;
	syslog->cl.tx_tout = TIMEOUT_MSEC;

	syslog->chan = mbox_request_channel(&syslog->cl, 0);
	init_completion(&syslog->c);

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
