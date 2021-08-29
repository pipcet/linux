// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2021 Pip Cet <pipcet@gmail.com>
 */

#include <linux/apple-asc.h>
#include <linux/delay.h>
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

struct apple_dcp_state {
	struct list_head list;
	size_t response_size;
	size_t response_off;
	size_t response_data_size;
};

struct apple_dcp {
	struct device *dev;
	struct rproc *rproc;
	/* Our upstream mailbox: infallibly sends data via the Apple mbox */
	struct mbox_client cl;
	struct mbox_chan *chan;
	/* Our downstream mailbox: fallibly receives data to be put in buffer */
	struct mbox_controller mbox_controller;
	struct mbox_chan downstream_chan;
	struct work_struct work;

	struct completion buffer_complete;

	spinlock_t lock;
	struct list_head states;
	void *buf;
	dma_addr_t buf_iova;
	size_t buf_size;
	size_t buf_off;
	u64 payload;
	u64 endpoint;
	bool init_complete;
};

size_t apple_dcp_msg_size(struct apple_dcp_msg_header *msg)
{
	return sizeof(*msg) + msg->len_input + msg->len_output;
}

/* XXX prototype for debugging */
static int apple_dcp_send_data(struct mbox_chan *chan, void *msg_header);

static void apple_dcp_work_func(struct work_struct *work)
{
	struct apple_dcp *dcp = container_of(work, struct apple_dcp, work);
	unsigned long flags;

	printk("work func\n");
	spin_lock_irqsave(&dcp->lock, flags);
	printk("work func locked\n");
	if (!dcp->buf_size) {
		spin_unlock_irqrestore(&dcp->lock, flags);
		return;
	}

	if (!dcp->buf) {
		void *buf;
		dma_addr_t iova;

		spin_unlock_irqrestore(&dcp->lock, flags);
		buf = dma_alloc_coherent(dcp->rproc->dev.parent, dcp->buf_size,
					 &iova, GFP_KERNEL);

		spin_lock_irqsave(&dcp->lock, flags);
		if (dcp->buf) {
			dma_free_coherent(dcp->rproc->dev.parent,
					  dcp->buf_size,
					  dcp->buf, iova);
		} else {
			struct apple_mbox_msg msg;
			msg.payload = 0;
			msg.endpoint = dcp->endpoint;

			msg.payload |= 0x0040;
			msg.payload |= iova << 16;

			mbox_copy_and_send(dcp->chan, &msg);
			dcp->buf = buf;
			dcp->buf_iova = iova;
		}
	}

	if (dcp->buf) {
		while (!list_empty(&dcp->states)) {
			printk("work func emptying\n");
			spin_unlock_irqrestore(&dcp->lock, flags);

			msleep(100);

			spin_lock_irqsave(&dcp->lock, flags);
		}
		if (list_empty(&dcp->states)) {
			printk("work func rewinding\n");
			dcp->buf_off = 0;
			memset(dcp->buf, 0, dcp->buf_size);
		}
	}
	spin_unlock_irqrestore(&dcp->lock, flags);
	complete_all(&dcp->buffer_complete);
}

static void apple_dcp_tx_done(struct mbox_client *cl, void *msg, int code)
{
	struct apple_dcp *dcp = container_of(cl, struct apple_dcp, cl);
	mbox_chan_txdone(&dcp->downstream_chan, code);
}

static void apple_dcp_receive_data(struct mbox_client *cl, void *msg_header)
{
	struct apple_dcp *dcp = container_of(cl, struct apple_dcp, cl);
	struct apple_mbox_msg *msg = msg_header;
	u64 payload = msg->payload;
	unsigned type = payload & 0xF;
	unsigned long flags;

	spin_lock_irqsave(&dcp->lock, flags);
	if (type == 1) {
		dev_info(dcp->dev, "init complete\n");
		dcp->init_complete = true;
		INIT_WORK(&dcp->work, apple_dcp_work_func);
		schedule_work(&dcp->work);
		spin_unlock_irqrestore(&dcp->lock, flags);
	} else if (type == 2) {
		struct apple_dcp_state *state = list_first_entry
			(&dcp->states, struct apple_dcp_state, list);
		struct apple_dcp_mbox_msg *response = devm_kzalloc
			(dcp->dev, state->response_size, GFP_KERNEL);
		BUG_ON(list_empty(&dcp->states));
		list_del(&state->list);
		if (response) {
			response->mbox = *msg;
			memcpy(response->dcp_data,
			       dcp->buf + state->response_off,
			       state->response_data_size);
		}
		spin_unlock_irqrestore(&dcp->lock, flags);
		mbox_chan_received_data(&dcp->downstream_chan, response);
		devm_kfree(dcp->dev, response);
		devm_kfree(dcp->dev, state);
	} else {
		dev_warn(dcp->dev, "unhandled message %016llx\n",
			 msg->payload);
		spin_unlock_irqrestore(&dcp->lock, flags);
	}
}

int apple_dcp_transaction(struct mbox_chan *chan,
			  struct apple_dcp_mbox_msg *msg)
{
	struct apple_dcp *dcp = chan->con_priv;
	struct apple_dcp_state *state;
	size_t dcp_msg_size = apple_dcp_msg_size(&msg->dcp);
	size_t offset;
	int ret;
	unsigned long flags;

	printk("buf_off %ld\n", (long)dcp->buf_off);

  again:
	spin_lock_irqsave(&dcp->lock, flags);

	if (!dcp->init_complete) {
		goto wait_retry;
	}

	if (dcp->buf == NULL) {
		goto schedule_wait_retry;
	}

	offset = dcp->buf_off;

	if (dcp->buf_off + dcp_msg_size > dcp->buf_size ||
	    dcp->buf_off + dcp_msg_size > 0x6000) {
		goto schedule_wait_retry;
	}

	state = devm_kzalloc(dcp->dev, sizeof(*state), GFP_KERNEL);
	if (!state) {
		spin_unlock_irqrestore(&dcp->lock, flags);
		return -ENOMEM;
	}

	state->response_size = sizeof(struct apple_dcp_mbox_msg) + msg->dcp.len_output + 0x100;
	state->response_off = dcp->buf_off + sizeof(struct apple_dcp_msg_header) + msg->dcp.len_input;
	state->response_data_size = msg->dcp.len_output;

	list_add(&state->list, &dcp->states);

	memset(dcp->buf + dcp->buf_off, 0, round_up(dcp_msg_size, 0x40));

	memcpy(dcp->buf + dcp->buf_off, &msg->dcp, sizeof(msg->dcp));
	dcp->buf_off += sizeof(msg->dcp);

	memcpy(dcp->buf + dcp->buf_off, msg->dcp_data, msg->dcp.len_input);
	dcp->buf_off += msg->dcp.len_input;

	dcp->buf_off += msg->dcp.len_output;
	dcp->buf_off = round_up(dcp->buf_off, 0x40);

	spin_unlock_irqrestore(&dcp->lock, flags);

	msg->mbox.payload &= 0xffff; /* preserve CTX, ACK, TYPE */
	msg->mbox.payload |= (offset << 16) & 0xffff0000; /* offset */
	msg->mbox.payload |= dcp_msg_size << 32; /* size */
	msg->mbox.endpoint = dcp->endpoint;
	ret = mbox_copy_and_send(dcp->chan, &msg->mbox);
	if (ret < 0) {
		/* XXX rewind buffer here? */
		return ret;
	}

	return 0;

  schedule_wait_retry:
	reinit_completion(&dcp->buffer_complete);
	INIT_WORK(&dcp->work, apple_dcp_work_func);
	schedule_work(&dcp->work);
  wait_retry:
	spin_unlock_irqrestore(&dcp->lock, flags);
	wait_for_completion(&dcp->buffer_complete);
	goto again;
}
EXPORT_SYMBOL(apple_dcp_transaction);

static int apple_dcp_send_data(struct mbox_chan *chan, void *msg_header)
{
	struct apple_dcp *dcp = chan->con_priv;
	struct apple_dcp_mbox_msg *msg = msg_header;
	struct apple_dcp_state *state;
	size_t dcp_msg_size = apple_dcp_msg_size(&msg->dcp);
	size_t offset;
	int ret;
	unsigned long flags;

	printk("buf_off %ld\n", (long)dcp->buf_off);

	spin_lock_irqsave(&dcp->lock, flags);

	if (!dcp->init_complete) {
		spin_unlock_irqrestore(&dcp->lock, flags);
		return -EBUSY;
	}

	state = devm_kzalloc(dcp->dev, sizeof(*state), GFP_KERNEL);
	if (!state) {
		spin_unlock_irqrestore(&dcp->lock, flags);
		return -ENOMEM;
	}

	state->response_size = sizeof(struct apple_dcp_mbox_msg) + msg->dcp.len_output + 0x100;
	state->response_off = dcp->buf_off + sizeof(struct apple_dcp_msg_header) + msg->dcp.len_input;
	state->response_data_size = msg->dcp.len_output;

	if (dcp->buf == NULL) {
		INIT_WORK(&dcp->work, apple_dcp_work_func);
		schedule_work(&dcp->work);
		spin_unlock_irqrestore(&dcp->lock, flags);
		return -EBUSY;
	}

	offset = dcp->buf_off;

	if (dcp->buf_off + dcp_msg_size > dcp->buf_size ||
	    dcp->buf_off + dcp_msg_size > 0x6000) {
		INIT_WORK(&dcp->work, apple_dcp_work_func);
		schedule_work(&dcp->work);
		spin_unlock_irqrestore(&dcp->lock, flags);
		return -EBUSY;
	}

	list_add(&state->list, &dcp->states);

	memset(dcp->buf + dcp->buf_off, 0, round_up(dcp_msg_size, 0x40));

	memcpy(dcp->buf + dcp->buf_off, &msg->dcp, sizeof(msg->dcp));
	dcp->buf_off += sizeof(msg->dcp);

	memcpy(dcp->buf + dcp->buf_off, msg->dcp_data, msg->dcp.len_input);
	dcp->buf_off += msg->dcp.len_input;

	dcp->buf_off += msg->dcp.len_output;
	dcp->buf_off = round_up(dcp->buf_off, 0x40);

	spin_unlock_irqrestore(&dcp->lock, flags);

	msg->mbox.payload &= 0xffff; /* preserve CTX, ACK, TYPE */
	msg->mbox.payload |= (offset << 16) & 0xffff0000; /* offset */
	msg->mbox.payload |= dcp_msg_size << 32; /* size */
	ret = mbox_copy_and_send(dcp->chan, &msg->mbox);
	if (ret < 0) {
		/* XXX rewind buffer here? */
		return ret;
	}

	return 0;
}

static struct mbox_chan_ops apple_dcp_mbox_chan_ops = {
	.send_data = apple_dcp_send_data,
};

static int apple_dcp_probe(struct platform_device *pdev)
{
	struct apple_dcp *dcp;
	int ret;
	u32 endpoint;

	dcp = devm_kzalloc(&pdev->dev, sizeof *dcp, GFP_KERNEL);
	if (!dcp)
		return -ENOMEM;

	dcp->dev = &pdev->dev;
	dcp->buf_size = 0x80000;
	dcp->rproc = platform_get_drvdata(to_platform_device(pdev->dev.parent));
	dcp->cl.dev = dcp->dev;
	dcp->cl.rx_callback = apple_dcp_receive_data;
	dcp->cl.tx_done = apple_dcp_tx_done;
	dcp->cl.tx_tout = ASC_TIMEOUT_MSEC;

	INIT_WORK(&dcp->work, apple_dcp_work_func);
	init_completion(&dcp->buffer_complete);
	ret = of_property_read_u32_index(dcp->dev->of_node, "mboxes", 1,
					 &endpoint);
	/* XXX */
	dcp->endpoint = endpoint;

	dcp->chan = mbox_request_channel(&dcp->cl, 0);

	if (IS_ERR(dcp->chan)) {
		dev_err(dcp->dev, "couldn't acquire mailbox channel\n");
		return PTR_ERR(dcp->chan);
	}

	INIT_LIST_HEAD(&dcp->states);
	dcp->downstream_chan.con_priv = dcp;

	dcp->mbox_controller.dev = dcp->dev;
	dcp->mbox_controller.ops = &apple_dcp_mbox_chan_ops;
	dcp->mbox_controller.chans = &dcp->downstream_chan;
	dcp->mbox_controller.num_chans = 1;
	dcp->mbox_controller.txdone_irq = true;

	devm_mbox_controller_register(dcp->dev, &dcp->mbox_controller);

	schedule_work(&dcp->work);

	return 0;
}

static const struct of_device_id apple_dcp_of_match[] = {
	{ .compatible = "apple,apple-asc-dcp" },
	{ },
};

static struct platform_driver apple_dcp_platform_driver = {
	.driver = {
		.name = "apple-asc-dcp",
		.of_match_table = apple_dcp_of_match,
	},
	.probe = apple_dcp_probe,
};

module_platform_driver(apple_dcp_platform_driver);
MODULE_DESCRIPTION("Apple SoC DCP Endpoint driver");
MODULE_LICENSE("GPL v2");
