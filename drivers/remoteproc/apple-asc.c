// SPDX-License-Identifier: GPL-2.0+
/*
 * Funneling mailbox-to-mailbox driver for Apple M1 SoC mailboxes
 * using the 8-bit endpoint protocol.
 *
 * This driver is simultaneously a mailbox client (for the highly
 * fallible single-channel mailbox implemented by Apple M1 hardware)
 * and a mailbox controller (one infallible somewhat-virtual mailbox
 * for each of the (potentially) 256 endpoints distinguished by the
 * mailbox protocol).
 *
 * It also handles CPU (but not mailbox) initialization (setting a
 * single bit) and the initial messages which cannot be sent over the
 * multi-channel mailbox.
 *
 * It does not handle runtime management even of EP0: there are
 * additional drivers for that, which don't need to know about the
 * hardware mailbox directly.
 *
 * This driver is also a remoteproc implementation. This reflects the
 * fact that there is a remote processor behind the mailbox, of
 * course, but it also gives us a handle (a phandle, in fact) on
 * what's on the other side of the mailbox channel that drivers see.
 *
 * Copyright (C) 2021 Pip Cet <pipcet@gmail.com>
 */

#include <linux/apple-asc.h>
#include <linux/delay.h>
#include <linux/mailbox_client.h>
#include <linux/mailbox_controller.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/remoteproc.h>
#include <linux/rwsem.h>
#include <linux/slab.h>

/* Message at the virtual mbox level. */
struct apple_asc_message {
	struct list_head list;
	struct mbox_chan *chan;

	struct apple_mbox_msg msg;
};

/* Locking is, unfortunately, a bit subtle: there's a spin lock, an
 * rwsem, and three lists of messages: waiting, queued, and sent.
 *
 * The spin lock guards access to the lists. It can only be acquired
 * if you hold the rwsem, in read or write mode.
 *
 * The rwsem is used in write mode to lock the mailbox exclusively
 * when communication has to be serialized. In read mode, it indicates
 * elements on the queued list, and its rwsem count is equal to the
 * length of the queued list.
 *
 * The subtle bit is that when we drop the rwsem in write mode, we try
 * to move messages from "waiting" to "queued" state as long as we can
 * grab the rwsem in read mode. We do so while holding the spinlock.
 */

struct apple_asc {
	struct rproc rproc;
	struct device *dev;

	void __iomem *reg;
	struct rw_semaphore rwsem;

	struct work_struct pwrack_work;
	struct completion rx_complete;
	struct completion tx_complete;
	struct completion pwrack_complete;

	/* The mailbox client interface: the single fallible mailbox
	 * going up. */
	struct mbox_client cl;
	struct mbox_chan *chan;

	/* The mailbox controller interface: up to 256 infallible mailboxes
	 * going down. */
	struct mbox_controller mbox_controller;
	struct mbox_chan *chans;
	unsigned long *started_chans;
	spinlock_t lock;
	/* waiting messages that we have not taken the rwsem for */
	struct list_head waiting_messages;
	/* queued messages that we have taken the rwsem for, but not yet
	 * sent. */
	struct list_head queued_messages;
	/* sent messages that we're waiting for a txdone for */
	struct list_head sent_messages;

	/* The last 64-bit payload received on EP0, before it's exposed
	 * as a mailbox. */
	u64 ep0_payload;

	struct dentry *debugfs_dir;
};

static void apple_asc_tx_tick_locked(struct apple_asc *asc)
{
	struct apple_asc_message *message;

	if (!list_empty(&asc->queued_messages)) {
		message = list_first_entry(&asc->queued_messages,
					   struct apple_asc_message, list);
		if (mbox_send_message(asc->chan, &message->msg) >= 0) {
			list_del(&message->list);
			list_add(&message->list, &asc->sent_messages);
		}
	}
}

struct mbox_chan *
apple_asc_lock_exclusively(struct rproc *rproc)
{
	struct apple_asc *asc = rproc->priv;

	down_write(&asc->rwsem);
	reinit_completion(&asc->tx_complete);

	return asc->chan;
}
EXPORT_SYMBOL(apple_asc_lock_exclusively);

void apple_asc_unlock(struct rproc *rproc, bool wait)
{
	struct apple_asc *asc = rproc->priv;
	unsigned long flags;
	struct list_head *msg, *n;

	if (wait)
		wait_for_completion(&asc->tx_complete);
	spin_lock_irqsave(&asc->lock, flags);
	up_write(&asc->rwsem);
	list_for_each_safe(msg, n, &asc->waiting_messages) {
		if (down_read_trylock(&asc->rwsem) <= 0)
			break;
		list_del(msg);
		list_add(msg, &asc->queued_messages);
	}
	apple_asc_tx_tick_locked(asc);
	spin_unlock_irqrestore(&asc->lock, flags);
}
EXPORT_SYMBOL(apple_asc_unlock);

static void apple_asc_pwrack_work(struct work_struct *work)
{
	struct apple_asc *asc = container_of(work, struct apple_asc,
					     pwrack_work);

	of_platform_populate(asc->dev->of_node, NULL, NULL, asc->dev);
}

void apple_asc_pwrack(struct rproc *rproc)
{
	struct apple_asc *asc = rproc->priv;
	int ret;

	complete_all(&asc->pwrack_complete);
	INIT_WORK(&asc->pwrack_work, apple_asc_pwrack_work);
	schedule_work(&asc->pwrack_work);
}
EXPORT_SYMBOL(apple_asc_pwrack);

static int ep0_send(struct apple_asc *asc, u64 payload)
{
	struct apple_mbox_msg msg;
	int ret;
	msg.payload = payload;
	msg.endpoint = 0;

	ret = mbox_copy_and_send(asc->chan, &msg);
	if (ret < 0)
		return ret;

	wait_for_completion(&asc->tx_complete);
	reinit_completion(&asc->tx_complete);

	return 0;
}

static int ep0_recv(struct apple_asc *asc, u64 *payload)
{
	int ret;

	wait_for_completion(&asc->rx_complete);

	reinit_completion(&asc->rx_complete);
	*payload = asc->ep0_payload;
	return 0;
}

static struct apple_asc_message *apple_asc_copy_message(void *msg, struct mbox_chan *chan)
{
	struct apple_asc_message *message = kzalloc(sizeof(*message),
						    GFP_KERNEL);
	if (!message)
		return NULL;

	memcpy(&message->msg, msg, sizeof(message->msg));
	message->chan = chan;

	return message;
}

static int apple_asc_send_data(struct mbox_chan *chan, void *msg)
{
	struct apple_asc *asc = chan->con_priv;
	struct apple_asc_message *message = apple_asc_copy_message(msg, chan);
	int ret;
	unsigned long flags;

	if (message == NULL)
		return -ENOMEM;

	WARN_ON((message->msg.endpoint & 0xff) != chan - asc->chans);

	spin_lock_irqsave(&asc->lock, flags);
	ret = down_read_trylock(&asc->rwsem);
	if (ret <= 0) {
		list_add(&message->list, &asc->waiting_messages);
	} else if (mbox_send_message(asc->chan, &message->msg) >= 0) {
		list_add(&message->list, &asc->sent_messages);
	} else {
		list_add(&message->list, &asc->queued_messages);
	}
	spin_unlock_irqrestore(&asc->lock, flags);

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
	unsigned long flags;

	spin_lock_irqsave(&asc->lock, flags);
	if (list_empty(&asc->sent_messages)) {
		complete_all(&asc->tx_complete);
		spin_unlock_irqrestore(&asc->lock, flags);
		return;
	}

	message = list_first_entry(&asc->sent_messages,
				   struct apple_asc_message,
				   list);
	//BUG_ON(msg != &message->msg);
	list_del(&message->list);

	apple_asc_tx_tick_locked(asc);
	spin_unlock_irqrestore(&asc->lock, flags);

	 /* XXX is this going to fail with lockdep debugging? There's
	  * no down_read_non_owner_trylock... */
	up_read_non_owner(&asc->rwsem);

	mbox_chan_txdone(message->chan, 0);
	kfree(message);
}

static int apple_asc_start_endpoint(struct apple_asc *asc, u64 index)
{
	int ret;
	apple_asc_lock_exclusively(&asc->rproc);

	ret = ep0_send(asc, EP0_START | (index << 32));

	apple_asc_unlock(&asc->rproc, false);

	return ret;
}

/* The single bit of hardware state we have: turn it on to start the CPU */
#define REG_CPU_CONTROL		0x44
#define  CPU_CONTROL_ENABLE	BIT(4)

static int apple_asc_startup(struct mbox_chan *chan)
{
	struct apple_asc *asc = chan->con_priv;
	int index = chan - asc->chans;
	int ret;

	if (test_bit(index, asc->started_chans))
		return 0;

	/* XXX, obviously */
	if (index >= 0x20 && index != 0x37) {
		/* XXX one second is too long, obviously, but .... */
		ret = wait_for_completion_timeout(&asc->pwrack_complete, HZ);
		if (ret <= 0)
			return -EPROBE_DEFER;
	}

	ret = apple_asc_start_endpoint(asc, index);
	set_bit(index, asc->started_chans);

	return ret;
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

	apple_asc_lock_exclusively(&asc->rproc);
	cpu_control = readl(asc->reg + REG_CPU_CONTROL);
	if (!(cpu_control & CPU_CONTROL_ENABLE)) {
		writel(cpu_control | CPU_CONTROL_ENABLE,
		       asc->reg + REG_CPU_CONTROL);
	} else {
		ret = ep0_send(asc, EP0_RESET);
		if (ret < 0)
			goto out;
	}

	ret = ep0_recv(asc, &payload);
	if (ret == -ETIME) {
		printk(KERN_WARNING "timeout after reset, attempting EHLLO\n");
		ret = ep0_send(asc, EP0_TYPE_EHLLO | EP0_EHLLO_MAGIC);
	} else if (ret < 0)
		goto out;
	else if ((payload & EP0_TYPE_MASK) == EP0_TYPE_HELLO) {
		payload = EP0_TYPE_EHLLO | (payload & U32_MAX);
		ret = ep0_send(asc, payload);
		if (ret < 0)
			goto out;
	}

	do {
		int page;
		ret = ep0_recv(asc, &payload);
		if (ret < 0)
			goto out;

		if ((payload & EP0_TYPE_MASK) != EP0_TYPE_EPMAP) {
			printk("unexpected message %016llx\n", payload);
			ret = -EINVAL;
			goto out;
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
			goto out;
	} while (!last);

	asc->chans = devm_kzalloc(asc->dev,
				  max_epnum * sizeof(asc->chans[0]),
				  GFP_KERNEL);
	if (!asc->chans)
		goto out;

	asc->started_chans = devm_kzalloc(asc->dev, BITS_TO_LONGS(max_epnum) *
					  sizeof(long), GFP_KERNEL);
	set_bit(0, asc->started_chans);

	for (epnum = 0; epnum < max_epnum; epnum++) {
		if (endpoint_mask[epnum >> 5] & BIT(epnum & 31))
			asc->chans[epnum].con_priv = asc;
	}

	asc->mbox_controller.dev = asc->dev;
	asc->mbox_controller.ops = &apple_asc_mbox_chan_ops;
	asc->mbox_controller.chans = asc->chans;
	asc->mbox_controller.num_chans = max_epnum;
	asc->mbox_controller.txdone_irq = true;

	devm_mbox_controller_register(asc->dev, &asc->mbox_controller);
	ret = 0;

  out:
	apple_asc_unlock(&asc->rproc, false);

	return ret;
}

static struct rproc_ops apple_asc_ops = {
	.attach = apple_asc_attach,
};

const struct of_device_id of_system_endpoint_matches[] = {
	{ .compatible = "apple,apple-asc-system-endpoint" },
	{ },
};

static int apple_asc_probe(struct platform_device *pdev)
{
	int ret;
	struct apple_asc *asc;
	struct rproc *rproc;
	const char *name = "unknown";
	struct device_node *np = pdev->dev.of_node;
	struct device_node *child;

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
	init_completion(&asc->pwrack_complete);
	init_rwsem(&asc->rwsem);
	asc->reg = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(asc->reg))
		return PTR_ERR(asc->reg);

	spin_lock_init(&asc->lock);
	INIT_LIST_HEAD(&asc->waiting_messages);
	INIT_LIST_HEAD(&asc->queued_messages);
	INIT_LIST_HEAD(&asc->sent_messages);
	asc->cl.dev = asc->dev;
	asc->cl.rx_callback = apple_asc_receive_data;
	asc->cl.tx_tout = ASC_TIMEOUT_MSEC;
	asc->cl.tx_done = apple_asc_tx_done;
	asc->chan = mbox_request_channel(&asc->cl, 0);

	if (IS_ERR(asc->chan))
		return PTR_ERR(asc->chan);

	ret = devm_rproc_add(asc->dev, &asc->rproc);
	if (ret < 0)
		return ret;

	for_each_child_of_node(np, child) {
		if (!of_match_node(of_system_endpoint_matches, child)) {
			printk("skipping node\n");
			continue;
		}
		printk("creating child\n");
		of_platform_device_create(child, NULL, asc->dev);
	}

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
MODULE_DESCRIPTION("Apple SoC ASC driver");
MODULE_LICENSE("GPL v2");
