// SPDX-License-Identifier: GPL-2.0+
/*
 * WARNING: This "hardware" is sensitive to timing. If you run into a
 * problem with this driver, and you add printks to debug it, you'll
 * suddenly find yourself with two problems: the printks may make the
 * code slow enough that it won't work. Or, you know, fast enough that
 * it won't work.
 *
 * Copyright (C) 2021 Pip Cet <pipcet@gmail.com>
 */

/* This implements the intermediate layer of a DCP driver: upstream,
 * it connects to an ASC mailbox for endpoint 0x37; downstream, it
 * provides four ping-pong mailboxes: two of these mailboxes, when
 * given a message, will modify the message, then send it back. The
 * other two will send a message and expect the client to send it
 * back, modified.
 *
 * Here, message means the actual pointer: the original sender must
 * guarantee the actual buffer will survive, and be writable, until
 * the "pong" is received, at which point any freeing must happen.
 */
#include <linux/apple-asc.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/list.h>
#include <linux/mailbox_client.h>
#include <linux/mailbox_controller.h>
#include <linux/memory.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/permalloc.h>
#include <linux/platform_device.h>
#include <linux/remoteproc.h>
#include <linux/slab.h>

struct apple_asc_dcp_shmem_msg {
	struct list_head list;

	int stream;
	int bufno;

	size_t size_raw;
	size_t size_roundup;

	size_t buf_off;
	bool slow_free;
	struct apple_dcp_msg *buf_msg;
	struct apple_dcp_msg *msg;
};

#define N_STREAMS		4
#define STREAM_COMMAND		0 /* ping pong: receive msg, send modified msg */
#define STREAM_CALLBACK		1 /* pong ping: send msg, receive modified msg */
#define STREAM_ASYNC		2 /* pong ping */
#define STREAM_NESTED_COMMAND	3 /* ping pong */

#define N_BUFFERS	3
#define BUF_COMMAND	0
#define BUF_CALLBACK	1
#define BUF_ASYNC	2

struct apple_asc_dcp {
	struct device *dev;
	struct rproc *rproc;
	/* Our upstream mailbox: infallibly sends data via the Apple mbox */
	struct mbox_client cl;
	struct mbox_chan *chan;
	/* Our downstream mailbox: fallibly receives data to be put in buffer */
	struct mbox_controller mbox_controller;
	struct mbox_chan downstream_chans[N_STREAMS];

	struct completion buffer_complete;

	spinlock_t lock;
	void *buf_va;
	size_t buf_size;
	dma_addr_t buf_iova;
	struct {
		void *base;
		size_t size;
		size_t off;
	} buf[N_BUFFERS];
	u64 endpoint;
	struct list_head shmem_messages;
};

#if 0
static void apple_dcp_msg_print(struct apple_dcp_msg *msg)
{
	printk("message %c%c%c%c, %d/%d\n",
	       FOURCC_CHARS(msg->header.code),
	       (int)msg->header.len_input,
	       (int)msg->header.len_output);

	print_hex_dump(KERN_INFO, "H:", DUMP_PREFIX_OFFSET, 16, 1, msg->data-12, 12, true);
	print_hex_dump(KERN_INFO, "I:", DUMP_PREFIX_OFFSET, 16, 1, msg->data, msg->header.len_input, true);
	print_hex_dump(KERN_INFO, "O:", DUMP_PREFIX_OFFSET, 16, 1, msg->data + msg->header.len_input, msg->header.len_output, true);
	//print_hex_dump(KERN_INFO, "C:", DUMP_PREFIX_OFFSET, 16, 1, msg->data - 12, msg->header.len_input + msg->header.len_output + 12, true);
}
#endif

static int ctx_to_stream(int ctx, bool ack)
{
	switch (ctx) {
	case 0:
		return ack ? STREAM_CALLBACK : STREAM_NESTED_COMMAND;
	case 2:
		BUG_ON(ack);
		return STREAM_COMMAND;
	case 3:
		BUG_ON(!ack);
		return STREAM_ASYNC;
	}

	BUG();
}

static int stream_to_bufno(int stream)
{
	switch (stream) {
	case STREAM_COMMAND:
	case STREAM_NESTED_COMMAND:
		return BUF_COMMAND;
	case STREAM_ASYNC:
		return BUF_ASYNC;
	case STREAM_CALLBACK:
		return BUF_CALLBACK;
	default:
		BUG();
	}
	return 0;
}

static u64 stream_to_ack(int stream)
{
	switch (stream) {
	case STREAM_COMMAND:
		return 0x242;
	case STREAM_NESTED_COMMAND:
		return 0x42;
	case STREAM_ASYNC:
		return 0x342;
	case STREAM_CALLBACK:
		return 0x42;
	default:
		BUG();
	}
}

static u64 stream_to_command(int stream)
{
	switch (stream) {
	case STREAM_COMMAND:
		return 0x202;
	case STREAM_NESTED_COMMAND:
		return 0x2;
	default:
		BUG();
	}
}

static void apple_asc_dcp_tx_done(struct mbox_client *cl, void *mbox_msg,
			      int code)
{
	struct apple_asc_dcp *dcp = container_of(cl, struct apple_asc_dcp, cl);
	struct apple_mbox_msg *mbox = mbox_msg;
	u64 payload = mbox->payload;
	unsigned type = FIELD_GET(GENMASK(3, 0), payload);

	if (type == 2) {
		unsigned ctx = FIELD_GET(GENMASK(11, 8), payload);
		bool ack = payload & BIT(6);
		int stream = ctx_to_stream(ctx, ack);

		mbox_chan_txdone(&dcp->downstream_chans[stream], code);
	}

	kfree(mbox_msg);
}

static int apple_asc_dcp_send_ack(struct apple_asc_dcp *dcp, int stream)
{
	struct apple_mbox_msg mbox;
	mbox.payload = stream_to_ack(stream);
	mbox.endpoint = dcp->endpoint;
	mbox_copy_and_send(dcp->chan, &mbox);
	return 0;
}

static int
apple_asc_dcp_buf_alloc(struct apple_asc_dcp *dcp, int bufno, size_t size,
			size_t *off)
{
	if (dcp->buf[bufno].off + size <= dcp->buf[bufno].size) {
		*off = dcp->buf[bufno].off;
		dcp->buf[bufno].off += size;
		return 0;
	}

	dev_warn(dcp->dev, "out of memory, this shouldn't happen!\n");
	return -ENOMEM;
}

/* Move the buffer pointer back to before the current message, unless
 * a nested message interferes. In that case, wait for the nested
 * message to be freed. */
static void
apple_asc_dcp_buf_free(struct apple_asc_dcp *dcp, struct apple_asc_dcp_shmem_msg *msg)
{
	int bufno = msg->bufno;
	size_t off = msg->buf_off;
	size_t size = msg->size_roundup;

	if (msg->slow_free || dcp->buf[bufno].off != off + size) {
		struct apple_asc_dcp_shmem_msg *msg;
		list_for_each_entry(msg, &dcp->shmem_messages, list) {
			if (msg->bufno == bufno && msg->buf_off > off) {
				msg->slow_free = true;
				return;
			}
		}

		off = 0;
		list_for_each_entry(msg, &dcp->shmem_messages, list) {
			if (msg->bufno == bufno && msg->buf_off + msg->size_roundup > off) {
				off = msg->buf_off + msg->size_roundup;
				return;
			}
		}
	}
	dcp->buf[bufno].off = off;
}

static struct apple_asc_dcp_shmem_msg *
apple_asc_dcp_find_shmem_msg(struct apple_asc_dcp *dcp, void *msg_header, int stream)
{
	struct apple_asc_dcp_shmem_msg *msg;
	list_for_each_entry(msg, &dcp->shmem_messages, list) {
		if (msg->msg == msg_header ||
		    msg->buf_msg == msg_header)
			return msg;
		if (msg_header)
			continue;
		if (msg->stream == stream)
			return msg;
	}
	return NULL;
}

static struct apple_asc_dcp_shmem_msg *
apple_asc_dcp_shmem_msg_in(struct apple_asc_dcp *dcp, void *msg_header, int stream)
{
	int bufno = stream_to_bufno(stream);
	size_t msg_size = apple_dcp_msg_size(msg_header);
	struct apple_asc_dcp_shmem_msg *shmem_msg = kzalloc(sizeof(*shmem_msg),
							    GFP_KERNEL);

	if (!shmem_msg)
		return NULL;

	shmem_msg->stream = stream;
	shmem_msg->bufno = bufno;

	shmem_msg->size_raw = msg_size;
	shmem_msg->size_roundup = 0;
	shmem_msg->buf_msg = msg_header;
	shmem_msg->msg = msg_header;
	list_add(&shmem_msg->list, &dcp->shmem_messages);

	return shmem_msg;
}

static struct apple_asc_dcp_shmem_msg *
apple_asc_dcp_shmem_msg_out(struct apple_asc_dcp *dcp, void *msg_header, int stream)
{
	int bufno = stream_to_bufno(stream);
	size_t msg_size = apple_dcp_msg_size(msg_header);
	int ret;
	struct apple_asc_dcp_shmem_msg *shmem_msg = kzalloc(sizeof(*shmem_msg),
							    GFP_KERNEL);

	if (!shmem_msg)
		return NULL;

	shmem_msg->stream = stream;
	shmem_msg->bufno = bufno;

	shmem_msg->size_raw = msg_size;
	shmem_msg->size_roundup = round_up(msg_size, 0x40);
	ret = apple_asc_dcp_buf_alloc(dcp, bufno, shmem_msg->size_roundup,
				      &shmem_msg->buf_off);
	if (ret) {
		kfree(shmem_msg);
		return ERR_PTR(ret);
	}
	shmem_msg->buf_msg = dcp->buf[bufno].base + shmem_msg->buf_off;
	shmem_msg->msg = msg_header;

	list_add(&shmem_msg->list, &dcp->shmem_messages);

	return shmem_msg;
}

/* Receive data from a client, create a shmem wrapper, copy it to the
 * shmem buf, and pass it on to upstream. */
static int apple_asc_dcp_pingpong_initial(struct apple_asc_dcp *dcp, void *msg_header,
				      int stream)
{
	struct apple_asc_dcp_shmem_msg* shmem_msg;
	struct apple_mbox_msg mbox;

	shmem_msg = apple_asc_dcp_shmem_msg_out(dcp, msg_header, stream);
	if (!shmem_msg) {
		return -ENOMEM;
	}

	memcpy(shmem_msg->buf_msg, msg_header, shmem_msg->size_raw);

	mbox.payload = stream_to_command(stream);
	mbox.payload |= (shmem_msg->buf_off << 16);
	mbox.payload |= (shmem_msg->size_raw << 32);
	mbox.endpoint = dcp->endpoint;
	mbox_copy_and_send(dcp->chan, &mbox);

	return 0;
}

/* Receive data from upstream, create a shmem wrapper, pass it on to
 * the client mailbox. */
static int apple_asc_dcp_pongping_initial(struct apple_asc_dcp *dcp, void *msg_header,
					  int stream)
{
	struct apple_asc_dcp_shmem_msg *shmem_msg;

	shmem_msg = apple_asc_dcp_shmem_msg_in(dcp, msg_header, stream);

	if (!shmem_msg) {
		return -ENOMEM;
	}

	mbox_chan_received_data(&dcp->downstream_chans[stream], shmem_msg->msg);
	return 0;
}

/* Receive response from upstream, copy it to the client memory area, pass it on to client */
static int apple_asc_dcp_pingpong_response(struct apple_asc_dcp *dcp, void *msg_header,
				       int stream)
{
	int bufno;
	struct apple_asc_dcp_shmem_msg *shmem_msg =
		apple_asc_dcp_find_shmem_msg(dcp, msg_header, stream);

	switch (stream) {
	case STREAM_COMMAND:
	case STREAM_NESTED_COMMAND:
		bufno = BUF_COMMAND;
		break;

	default:
		BUG();
	}
	BUG_ON(!shmem_msg);
	memcpy(shmem_msg->msg, shmem_msg->buf_msg, shmem_msg->size_raw);
	list_del(&shmem_msg->list);
	apple_asc_dcp_buf_free(dcp, shmem_msg);
	mbox_chan_received_data(&dcp->downstream_chans[stream], shmem_msg->msg);
	kfree(shmem_msg);

	return 0;
}

/* Receive response from client, pass it on to upstream */
static int apple_asc_dcp_pongping_response(struct apple_asc_dcp *dcp, void *msg_header,
				       int stream)
{
	struct apple_asc_dcp_shmem_msg *shmem_msg =
		apple_asc_dcp_find_shmem_msg(dcp, msg_header, stream);

	BUG_ON(!shmem_msg);
	apple_asc_dcp_send_ack(dcp, stream);

	list_del(&shmem_msg->list);
	kfree(shmem_msg);

	return 0;
}

static void apple_asc_dcp_receive_data(struct mbox_client *cl, void *mbox_msg)
{
	struct apple_asc_dcp *dcp = container_of(cl, struct apple_asc_dcp, cl);
	struct apple_mbox_msg *msg = mbox_msg;
	u64 payload = msg->payload;
	unsigned long flags;
	unsigned type = FIELD_GET(GENMASK(3, 0), payload);
	bool ack = payload & BIT(6);
	unsigned ctx = FIELD_GET(GENMASK(11,  8), payload);
	unsigned off = FIELD_GET(GENMASK(31, 16), payload);
	int stream;
	int bufno;

	spin_lock_irqsave(&dcp->lock, flags);
	if (type == 1) {
		complete_all(&dcp->buffer_complete);
		spin_unlock_irqrestore(&dcp->lock, flags);
		return;
	}
	if (!dcp->buf_va) {
		dev_warn(dcp->dev, "ignoring early message!\n");
		spin_unlock_irqrestore(&dcp->lock, flags);
		return;
	}

	if (type != 2)
		goto unexpected;
	if (ack) {
		switch (ctx) {
		case 0:
			stream = STREAM_NESTED_COMMAND;
			bufno = BUF_COMMAND;
			break;
		case 2:
			stream = STREAM_COMMAND;
			bufno = BUF_COMMAND;
			break;
		default:
			goto unexpected;
		}

		apple_asc_dcp_pingpong_response(dcp, NULL, stream);
	} else {
		void *buf_msg;
		switch (ctx) {
		case 0:
			stream = STREAM_CALLBACK;
			bufno = BUF_CALLBACK;
			break;
		case 3:
			stream = STREAM_ASYNC;
			bufno = BUF_ASYNC;
			break;
		default:
			goto unexpected;
		}
		buf_msg = dcp->buf[bufno].base + off;

		apple_asc_dcp_pongping_initial(dcp, buf_msg, stream);
	}
	spin_unlock_irqrestore(&dcp->lock, flags);
	return;

unexpected:
	spin_unlock_irqrestore(&dcp->lock, flags);
	dev_warn(dcp->dev, "unexpected message %016llx\n",
		 msg->payload);
}

static int apple_asc_dcp_mbox_send_data(struct mbox_chan *chan, void *msg_header)
{
	struct apple_asc_dcp *dcp = chan->con_priv;
	int stream = chan - dcp->downstream_chans;

	switch (stream) {
	case STREAM_COMMAND:
	case STREAM_NESTED_COMMAND:
		return apple_asc_dcp_pingpong_initial(dcp, msg_header, stream);
	case STREAM_CALLBACK:
	case STREAM_ASYNC:
		return apple_asc_dcp_pongping_response(dcp, msg_header, stream);
	}
	BUG();
}

static struct mbox_chan_ops apple_asc_dcp_mbox_chan_ops = {
	.send_data = apple_asc_dcp_mbox_send_data,
};

static int apple_asc_dcp_probe(struct platform_device *pdev)
{
	struct apple_asc_dcp *dcp;
	int ret;
	u32 endpoint = 0x37;
	int i;
	dma_addr_t iova;
	struct apple_mbox_msg msg;

	dcp = devm_kzalloc(&pdev->dev, sizeof(*dcp), GFP_KERNEL);
	if (!dcp)
		return -ENOMEM;

	dcp->dev = &pdev->dev;
	dcp->buf_size = 0x200000;
	dcp->rproc = platform_get_drvdata(to_platform_device(pdev->dev.parent));
	dcp->cl.dev = dcp->dev;
	dcp->cl.rx_callback = apple_asc_dcp_receive_data;
	dcp->cl.tx_done = apple_asc_dcp_tx_done;
	dcp->cl.tx_tout = ASC_TIMEOUT_MSEC;

	spin_lock_init(&dcp->lock);
	init_completion(&dcp->buffer_complete);
	ret = of_property_read_u32_index(dcp->dev->of_node, "mboxes", 1,
					 &endpoint);
	dcp->endpoint = endpoint;

	dcp->chan = mbox_request_channel(&dcp->cl, 0);
	if (IS_ERR(dcp->chan)) {
		dev_err(dcp->dev, "couldn't acquire mailbox channel\n");
		return PTR_ERR(dcp->chan);
	}

	INIT_LIST_HEAD(&dcp->shmem_messages);
	for (i = 0; i < N_STREAMS; i++)
		dcp->downstream_chans[i].con_priv = dcp;

	dcp->mbox_controller.dev = dcp->dev;
	dcp->mbox_controller.ops = &apple_asc_dcp_mbox_chan_ops;
	dcp->mbox_controller.chans = dcp->downstream_chans;
	dcp->mbox_controller.num_chans = N_STREAMS;
	dcp->mbox_controller.txdone_irq = true;

	dma_set_mask_and_coherent(dcp->dev, DMA_BIT_MASK(32));
	dcp->buf_va = dma_alloc_coherent(dcp->dev, dcp->buf_size,
					 &iova, GFP_KERNEL);
	permalloc_memory(dcp->dev, dcp->buf_va, dcp->buf_size);

	if (!dcp->buf_va)
		return -ENOMEM;

	memset(dcp->buf_va, 0, dcp->buf_size);
	dcp->buf_iova = iova;
	dcp->buf[BUF_COMMAND].base = dcp->buf_va;
	dcp->buf[BUF_COMMAND].size = 0x8000;
	dcp->buf[BUF_COMMAND].off = 0;
	dcp->buf[BUF_CALLBACK].base = dcp->buf_va + 0x60000;
	dcp->buf[BUF_CALLBACK].size = 0x8000;
	dcp->buf[BUF_CALLBACK].off = 0;
	dcp->buf[BUF_ASYNC].base = dcp->buf_va + 0x40000;
	dcp->buf[BUF_ASYNC].size = 0x20000;
	dcp->buf[BUF_ASYNC].off = 0;
	msg.payload = 0;
	msg.endpoint = dcp->endpoint;

	msg.payload |= 0x0040;
	msg.payload |= iova << 16;
	msg.payload |= 0xfLL << 48;

	mbox_copy_and_send(dcp->chan, &msg);

	wait_for_completion(&dcp->buffer_complete);

	devm_mbox_controller_register(dcp->dev, &dcp->mbox_controller);

	of_platform_populate(pdev->dev.of_node, NULL, NULL, &pdev->dev);

	return 0;
}

static const struct of_device_id apple_asc_dcp_of_match[] = {
	{ .compatible = "apple,apple-asc-dcp" },
	{ },
};

static struct platform_driver apple_asc_dcp_platform_driver = {
	.driver = {
		.name = "apple-asc-dcp",
		.of_match_table = apple_asc_dcp_of_match,
	},
	.probe = apple_asc_dcp_probe,
};

module_platform_driver(apple_asc_dcp_platform_driver);
MODULE_DESCRIPTION("Apple SoC DCP Endpoint driver");
MODULE_LICENSE("GPL v2");
