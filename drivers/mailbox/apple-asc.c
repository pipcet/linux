// SPDX-License-Identifier: GPL-2.0+
/*
 * Funneling mailbox-to-mailbox driver for Apple M1 SoC mailboxes
 * using the 8-bit endpoint protocol.
 *
 * This driver is simultaneously a mailbox client (for the highly
 * fallible single-channel mailbox implemented by Apple M1 hardware)
 * and a mailbox controller (one infallible somewhat-virtual mailbox
 * for each of the (potentially) 256 endpoints distinguished by the
 * mailbox protocol.
 *
 * It also handles CPU (but not mailbox) initialization (setting a
 * single bit) and the initial messages which cannot be sent over the
 * multi-channel mailbox.
 *
 * It does not handle runtime management even of EP0: there are
 * additional drivers for that, which don't need to know about the
 * hardware mailbox directly.
 *
 * Copyright (C) 2021 Pip Cet <pipcet@gmail.com>
 */

#include <linux/mailbox_client.h>
#include <linux/mailbox_controller.h>
#include <linux/remoteproc.h>
#include <linux/platform_device.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/slab.h>

#define TIMEOUT_MSEC	      800 /* 800 ms should be plenty. */

/* A message at the physical mbox level. 64-bit payload plus 64-bit
 * information which includes, in its low-order bits, an 8-bit endpoint. */
struct apple_mbox_msg {
	u64 payload;
	u64 endpoint;
};

/* Message at the virtual mbox level. */
struct apple_asc_message {
	struct list_head list;
	struct mbox_chan *chan;

	struct apple_mbox_msg msg;
};

struct apple_asc {
	struct rproc rproc;
	struct device *dev;

	void __iomem *reg;
	struct mutex lock; /* XXX */

	struct completion rx_complete;
	struct completion tx_complete;

	/* The mailbox client interface: the single fallible mailbox
	 * going up. */
	struct mbox_client cl;
	struct mbox_chan *chan;

	/* The mailbox controller interface: up to 256 infallible mailboxes
	 * going down. */
	struct mbox_controller mbox_controller;
	struct mbox_chan *chans;
	struct list_head queued_messages;
	struct list_head sent_messages;

	/* The last 64-bit payload received on EP0, before its exposed
	 * as a mailbox. */
	u64 ep0_payload;

	struct dentry *debugfs_dir;
};

/* HACK alert: we'd like to simply act as a client for our own
 * infallible mailbox controller, but we don't want circular
 * references in the DT; also, we don't know how many channels there
 * are actually going to be until later. */
static int ep0_send(struct apple_asc *asc, u64 payload)
{
	struct apple_mbox_msg msg;
	int ret;
	msg.payload = payload;
	msg.endpoint = 0;
	ret = mbox_send_message(asc->chan, &msg);
	if (ret < 0)
		return ret;

	ret = wait_for_completion_killable_timeout
		(&asc->tx_complete, 5 * HZ);
	if (ret < 0)
		return ret;

	reinit_completion(&asc->tx_complete);
	return 0;
}

static int ep0_recv(struct apple_asc *asc, u64 *payload)
{
	int ret;

	ret = wait_for_completion_killable_timeout
		(&asc->rx_complete, 5 * HZ);
	if (ret < 0)
		return ret;

	reinit_completion(&asc->rx_complete);
	*payload = asc->ep0_payload;
	return 0;
}

static struct apple_asc_message *apple_asc_copy_message(void *msg, struct mbox_chan *chan)
{
	struct apple_asc_message *message = kzalloc(sizeof *message,
						    GFP_KERNEL);
	if (!message)
		return NULL;

	memcpy(&message->msg, msg, sizeof message->msg);
	message->chan = chan;

	return message;
}

static int apple_asc_send_data(struct mbox_chan *chan, void *msg)
{
	struct apple_asc *asc = chan->con_priv;
	struct apple_asc_message *message = apple_asc_copy_message(msg, chan);

	if (message == NULL)
		return -ENOMEM;

	if (mbox_send_message(asc->chan, msg) >= 0) {
		list_add(&message->list, &asc->sent_messages);
	} else {
		list_add(&message->list, &asc->queued_messages);
	}

	return 0;
}

static void apple_asc_receive_data(struct mbox_client *cl, void *msg)
{
	struct apple_asc *asc = container_of(cl, struct apple_asc, cl);
	struct apple_mbox_msg *mbox_msg = msg;
	int ep = mbox_msg->endpoint & 0xff;

	if (asc->chans && asc->chans[ep].cl)
		mbox_chan_received_data(&asc->chans[ep], msg);
	else if (ep == 0) {
		asc->ep0_payload = mbox_msg->payload;
		complete_all(&asc->rx_complete);
	} else
		printk(KERN_WARNING "unexpected message %016llx %016llx\n",
		       mbox_msg->payload, mbox_msg->endpoint);
}

static void apple_asc_tx_done(struct mbox_client *cl, void *msg, int code)
{
	struct apple_asc *asc = container_of(cl, struct apple_asc, cl);
	struct apple_asc_message *message;

	if (list_empty(&asc->sent_messages)) {
		complete_all(&asc->tx_complete);
		return;
	}

	message =
		list_first_entry(&asc->sent_messages, struct apple_asc_message,
				 list);
	mbox_chan_txdone(message->chan, 0);
	list_del(&message->list);
	kfree(message);

	if (!list_empty(&asc->queued_messages)) {
		message = list_first_entry(&asc->queued_messages,
					   struct apple_asc_message, list);
		if (mbox_send_message(asc->chan, &message->msg)) {
			list_del(&message->list);
			list_add(&message->list, &asc->sent_messages);
		}
	} else {
		complete_all(&asc->tx_complete);
	}
}

#define EP0_TYPE_MASK     (0xfffULL << 52)
#define EP0_TYPE_HELLO    (0x001ULL << 52)
#define EP0_TYPE_EHLLO    (0x002ULL << 52)
#define EP0_TYPE_START    (0x005ULL << 52)
#define EP0_TYPE_RESET    (0x006ULL << 52)
#define EP0_TYPE_EPMAP    (0x008ULL << 52)
#define EP0_TYPE_PWRACK   (0x00bULL << 52)

#define EP0_START (EP0_TYPE_START | 0x0002)
#define EP0_EHLLO (EP0_TYPE_EHLLO | 0x0001)
#define EP0_RESET (EP0_TYPE_RESET | 0x0220)

#define EP0_EHLLO_MAGIC   0x000b000b

#define EP0_EPMAP_LAST    (0x8ULL << 48)
#define EP0_EPMAP_PAGE(p) (((p) >> 32) & 0x7ULL)

static int apple_asc_start_endpoint(struct apple_asc *asc, u64 index)
{
	return ep0_send(asc, EP0_START | (index << 32));
}

/* The single bit of hardware state we have: turn it on to start the CPU */
#define REG_CPU_CONTROL 0x44
#define  CPU_CONTROL_ENABLE BIT(4)

static int apple_asc_startup(struct mbox_chan *chan)
{
	struct apple_asc *asc = chan->con_priv;
	return apple_asc_start_endpoint(asc, chan - asc->chans);
}

static struct mbox_chan_ops apple_asc_mbox_chan_ops = {
	.send_data = apple_asc_send_data,
	.startup = apple_asc_startup,
};

static int apple_asc_attach(struct rproc *rproc)
{
	struct apple_asc *asc = rproc->priv;
	u32 cpu_control;
	int epnum;
	int max_epnum;
	int ret;
	u64 payload = 0;
	u32 endpoint_mask[8];
	bool last;

	cpu_control = readl(asc->reg + REG_CPU_CONTROL);
	if (!(cpu_control & CPU_CONTROL_ENABLE)) {
		writel(cpu_control | CPU_CONTROL_ENABLE,
		       asc->reg + REG_CPU_CONTROL);
	} else {
		ret = ep0_send(asc, EP0_RESET);
		if (ret < 0)
			return ret;
	}

	ret = ep0_recv(asc, &payload);
	if (ret == -ETIME) {
		printk(KERN_WARNING "timeout after reset, attempting EHLLO\n");
		ret = ep0_send(asc, EP0_TYPE_EHLLO | EP0_EHLLO_MAGIC);
	} else if (ret < 0)
		return ret;
	else if ((payload & EP0_TYPE_MASK) == EP0_TYPE_HELLO) {
		payload = EP0_TYPE_EHLLO | (payload & U32_MAX);
		ret = ep0_send(asc, payload);
		if (ret < 0)
			return ret;
	}

	do {
		int page;
		ret = ep0_recv(asc, &payload);
		if (ret < 0)
			return ret;

		if ((payload & EP0_TYPE_MASK) != EP0_TYPE_EPMAP) {
			printk("unexpected message %016llx\n", payload);
			return -EINVAL;
		}

		page = EP0_EPMAP_PAGE(payload);
		last = payload & EP0_EPMAP_LAST;
		endpoint_mask[page] = payload & U32_MAX;
		max_epnum = (page + 1) * 32;
		/* provide a single CPU-side endpoint, I think. */
		payload &= ~(u64)U32_MAX;
		if (page == 0)
			payload |= 1;
		ret = ep0_send(asc, payload);
		if (ret < 0)
			return ret;
	} while (!last);

	asc->chans = devm_kzalloc(asc->dev,
				  max_epnum * sizeof(asc->chans[0]),
				  GFP_KERNEL);
	if (!asc->chans)
		return -ENOMEM;

	for (epnum = 0; epnum < max_epnum; epnum++) {
		if (endpoint_mask[epnum >> 5] & (1 << (epnum & 31)))
			asc->chans[epnum].con_priv = asc;
	}

	asc->mbox_controller.dev = asc->dev;
	asc->mbox_controller.ops = &apple_asc_mbox_chan_ops;
	asc->mbox_controller.chans = asc->chans;
	asc->mbox_controller.num_chans = max_epnum;
	asc->mbox_controller.txdone_irq = true;

	devm_mbox_controller_register(asc->dev, &asc->mbox_controller);

	return 0;
}

static struct rproc_ops apple_asc_ops = {
	.attach = apple_asc_attach,
};

static int apple_asc_probe(struct platform_device *pdev)
{
	int ret;
	struct apple_asc *asc;
	struct resource *rsrc;
	struct rproc *rproc;
	const char *name = "unknown";
	struct device_node *np = pdev->dev.of_node;

	of_property_read_string(pdev->dev.of_node, "rproc-name", &name);
	rproc = rproc_alloc(&pdev->dev, name, &apple_asc_ops, NULL,
			    sizeof(*asc) - sizeof(struct rproc));

	if (!rproc)
		return -ENOMEM;

	asc = container_of(rproc, struct apple_asc, rproc);
	platform_set_drvdata(pdev, asc);
	asc->rproc.state = RPROC_DETACHED;
	asc->rproc.priv = asc;
	asc->dev = &pdev->dev;
	init_completion(&asc->rx_complete);
	init_completion(&asc->tx_complete);
	rsrc = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	asc->reg = devm_ioremap_resource(asc->dev, rsrc);
	if (IS_ERR(asc->reg))
		return PTR_ERR(asc->reg);

	INIT_LIST_HEAD(&asc->queued_messages);
	INIT_LIST_HEAD(&asc->sent_messages);
	asc->cl.dev = asc->dev;
	asc->cl.rx_callback = apple_asc_receive_data;
	asc->cl.tx_tout = TIMEOUT_MSEC;
	asc->cl.tx_done = apple_asc_tx_done;
	asc->chan = mbox_request_channel(&asc->cl, 0);

	if (IS_ERR(asc->chan))
		return PTR_ERR(asc->chan);

	ret = devm_rproc_add(asc->dev, &asc->rproc);
	if (ret < 0)
		return ret;

	ret = of_platform_populate(np, NULL, NULL, asc->dev);
	if (ret)
		return ret;

	return 0;
}

static const struct of_device_id apple_asc_of_match[] = {
	{ .compatible = "apple,apple-asc" },
	{ }
};

static struct platform_driver apple_asc_platform_driver = {
	.driver = {
		.name = "apple-asc",
		.of_match_table = apple_asc_of_match,
	},
	.probe = apple_asc_probe,
};

module_platform_driver(apple_asc_platform_driver);
MODULE_DESCRIPTION("Apple SoC ASC \"bare\" mailbox driver");
MODULE_LICENSE("GPL v2");
