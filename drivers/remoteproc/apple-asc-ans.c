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
	struct work_struct work;

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

size_t apple_ans_msg_size(struct apple_ans_msg_header *msg)
{
	return sizeof(*msg) + msg->len_input + msg->len_output;
}

/* XXX prototype for debugging */
static int apple_ans_send_data(struct mbox_chan *chan, void *msg_header);

static void apple_ans_work_func(struct work_struct *work)
{
	struct apple_ans *ans = container_of(work, struct apple_ans, work);
	unsigned long flags;

	spin_lock_irqsave(&ans->lock, flags);
	if (!ans->buf_size) {
		spin_unlock_irqrestore(&ans->lock, flags);
		return;
	}

	if (!ans->buf) {
		void *buf;
		dma_addr_t iova;
		void *l1, *l2;
		u64 l2_iova;

		spin_unlock_irqrestore(&ans->lock, flags);
		buf = dma_alloc_coherent(ans->rproc->dev.parent, ans->buf_size,
					 &iova, GFP_KERNEL);

		spin_lock_irqsave(&ans->lock, flags);
#if 0 /* temporary code until DART works */
		ans->buf_iova = iova;
		iova = 0xf80000000;
		l1 = devm_memremap(ans->dev, 0xbfff60000, 16384, MEMREMAP_WB);
		dev_warn(ans->rproc->dev.parent, "allocating dma chunk");
		l2 = dma_alloc_coherent(ans->rproc->dev.parent, 16384, &l2_iova, GFP_KERNEL);
		printk("dma_alloc_coherent returned %016llx!\n", l2);
		dev_warn(ans->rproc->dev.parent, "allocating dma chunk");
		*(volatile u64 *)(l2 + 0) = ans->buf_iova | 3;
		*(volatile u64 *)(l1 + (0x40 << 3)) = l2_iova | 1;
#else
#endif
		if (ans->buf) {
			dma_free_coherent(ans->rproc->dev.parent,
					  ans->buf_size,
					  ans->buf, iova);
		} else {
			struct apple_mbox_msg msg;
			msg.payload = 0;
			msg.endpoint = ans->endpoint;

			msg.payload |= 0x0040;
			msg.payload |= iova << 16;

			mbox_copy_and_send(ans->chan, &msg);
			ans->buf = buf;
			ans->buf_iova = iova;
		}
	}

	if (ans->buf) {
		if (list_empty(&ans->states)) {
			ans->buf_off = 0;
			memset(ans->buf, 0, ans->buf_size);
		}
	}
	spin_unlock_irqrestore(&ans->lock, flags);
}

static void apple_ans_tx_done(struct mbox_client *cl, void *msg, int code)
{
	struct apple_ans *ans = container_of(cl, struct apple_ans, cl);
	mbox_chan_txdone(&ans->downstream_chan, code);
	kfree(msg);
}

static void apple_ans_receive_data(struct mbox_client *cl, void *msg_header)
{
	struct apple_ans *ans = container_of(cl, struct apple_ans, cl);
	struct apple_mbox_msg *msg = msg_header;
	u64 payload = msg->payload;
	unsigned type = payload & 0xF;
	unsigned long flags;

	spin_lock_irqsave(&ans->lock, flags);
	if (type == 1) {
		dev_info(ans->dev, "init complete\n");
		ans->init_complete = true;
		INIT_WORK(&ans->work, apple_ans_work_func);
		schedule_work(&ans->work);
		spin_unlock_irqrestore(&ans->lock, flags);
	} else if (type == 2) {
		struct apple_ans_state *state = list_first_entry
			(&ans->states, struct apple_ans_state, list);
		struct apple_ans_mbox_msg *response = kzalloc
			(state->response_size, GFP_KERNEL);
		list_del(&state->list);
		if (response) {
			response->mbox = *msg;
			memcpy(response->ans_data,
			       ans->buf + state->response_off,
			       state->response_data_size);
		}
		spin_unlock_irqrestore(&ans->lock, flags);
		mbox_chan_received_data(&ans->downstream_chan, response);
		kfree(response);
		kfree(state);
	} else {
		dev_warn(ans->dev, "unhandled message %016llx\n",
			 msg->payload);
		spin_unlock_irqrestore(&ans->lock, flags);
	}
}

static int apple_ans_send_data(struct mbox_chan *chan, void *msg_header)
{
	struct apple_ans *ans = chan->con_priv;
	struct apple_ans_mbox_msg *msg = msg_header;
	struct apple_ans_state *state;
	size_t ans_msg_size = apple_ans_msg_size(&msg->ans);
	size_t offset;
	int ret;
	unsigned long flags;

	printk("buf_off %ld\n", (long)ans->buf_off);

	spin_lock_irqsave(&ans->lock, flags);

	if (!ans->init_complete) {
		spin_unlock_irqrestore(&ans->lock, flags);
		return -EBUSY;
	}

	state = devm_kzalloc(ans->dev, sizeof *state, GFP_KERNEL);
	if (!state) {
		spin_unlock_irqrestore(&ans->lock, flags);
		return -ENOMEM;
	}

	state->response_size = sizeof(struct apple_ans_mbox_msg) + msg->ans.len_output + 0x100;
	state->response_off = ans->buf_off + sizeof(struct apple_ans_msg_header) + msg->ans.len_input;
	state->response_data_size = msg->ans.len_output;

	list_add(&state->list, &ans->states);

	if (ans->buf == NULL) {
		INIT_WORK(&ans->work, apple_ans_work_func);
		schedule_work(&ans->work);
		spin_unlock_irqrestore(&ans->lock, flags);
		return -EBUSY;
	}

	offset = ans->buf_off;

	if (ans->buf_off + ans_msg_size > ans->buf_size) {
		INIT_WORK(&ans->work, apple_ans_work_func);
		schedule_work(&ans->work);
		spin_unlock_irqrestore(&ans->lock, flags);
		return -EBUSY;
	}

	memset(ans->buf + ans->buf_off, 0, round_up(ans_msg_size, 0x40));

	memcpy(ans->buf + ans->buf_off, &msg->ans, sizeof(msg->ans));
	ans->buf_off += sizeof(msg->ans);

	memcpy(ans->buf + ans->buf_off, msg->ans_data, msg->ans.len_input);
	ans->buf_off += msg->ans.len_input;

	ans->buf_off += msg->ans.len_output;
	ans->buf_off = round_up(ans->buf_off, 0x40);

	spin_unlock_irqrestore(&ans->lock, flags);

	msg->mbox.payload &= 0xffff; /* preserve CTX, ACK, TYPE */
	msg->mbox.payload |= (offset << 16) & 0xffff0000; /* offset */
	msg->mbox.payload |= ans_msg_size << 32; /* size */
	ret = mbox_copy_and_send(ans->chan, &msg->mbox);
	if (ret < 0) {
		/* XXX rewind buffer here? */
		return ret;
	}

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
	ans->buf_size = 0x8000;
	ans->rproc = platform_get_drvdata(to_platform_device(pdev->dev.parent));
	ans->cl.dev = ans->dev;
	ans->cl.rx_callback = apple_ans_receive_data;
	ans->cl.tx_done = apple_ans_tx_done;
	ans->cl.tx_tout = ASC_TIMEOUT_MSEC;

	INIT_WORK(&ans->work, apple_ans_work_func);
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

	INIT_LIST_HEAD(&ans->states);
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
