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
#include <linux/platform_device.h>
#include <linux/remoteproc.h>
#include <linux/slab.h>

#define DCP_MSG_INIT_W(m) do {					\
		(m)->header.len_input = sizeof((m)->in);	\
		(m)->header.len_output = sizeof((m)->out);	\
	} while (0)
#define DCP_MSG_INIT_R(m) do {						\
		BUG_ON((m)->header.len_input != sizeof((m)->in));	\
		BUH_ON((m)->header.len_output != sizeof((m)->out));	\
	} while (0)

struct apple_dcp_remote_buffer {
	struct list_head list;
	u32 id;
	u64 dva;
	void *va;
	u64 size;
};

struct apple_dcp_transaction_state {
	struct list_head list;
	struct apple_dcp_mbox_msg *msg;
	struct apple_dcp_header *header;
	void *data;
	struct completion complete;
	void *buf_base;
	size_t buf_off;
};

/*static*/ struct apple_fourcc {
	char fourcc[4];
	char *desc;
} fourcc[] = {
	{ "A000", "late init signal; EP8 must be up" },
	{ "A029", "setup_video_limits" },
	{ "A034", "update_notify_clients_dcp" },
	{ "A357", "set_create_DFB" },
	{ "A412", "set digital output mode" },
	{ "A426", "get_color_remap_mode" },
	{ "A443", "" },
	{ "A447", "" },
	{ "A454", "" },
	{ "A460", "" },
	{ "A463", "" },
	{ "A468", "" },
	{ "D000", "" },
	{ "D001", "" },
	{ "D003", "" },
	{ "D101", "" },
	{ "D107", "" },
	{ "D108", "" },
	{ "D109", "" },
	{ "D110", "" },
	{ "D111", "" },
	{ "D116", "" },
	{ "D118", "" },
	{ "D120", "" },
	{ "D122", "" },
	{ "D123", "" },
	{ "D124", "" },
	{ "D206", "" },
	{ "D207", "" },
	{ "D401", "" },
	{ "D411", "" },
	{ "D413", "" },
	{ "D414", "" },
	{ "D415", "" },
	{ "D451", "" },
	{ "D452", "" },
	{ "D552", "" },
	{ "D561", "" },
	{ "D563", "" },
	{ "D565", "" },
	{ "D567", "" },
	{ "D574", "" },
	{ }
};

#define N_STREAMS		4
#define STREAM_COMMAND		0
#define STREAM_CALLBACK		1
#define STREAM_ASYNC		2
#define STREAM_NESTED_COMMAND	3

#define N_BUFFERS	3
#define BUF_COMMAND	0
#define BUF_CALLBACK	1
#define BUF_ASYNC	2

struct apple_dcp {
	struct device *dev;
	struct rproc *rproc;
	/* Our upstream mailbox: infallibly sends data via the Apple mbox */
	struct mbox_client cl;
	struct mbox_chan *chan;
	/* Our downstream mailbox: fallibly receives data to be put in buffer */
	struct mbox_controller mbox_controller;
	struct mbox_chan downstream_chans[N_STREAMS];
	struct work_struct work;
	struct work_struct work_hardware_boot;
	struct work_struct work_map_physical;

	struct completion buffer_complete;

	void *map_physical_buf;
	spinlock_t lock;
	void *buf_va;
	size_t buf_va_size;
	dma_addr_t buf_iova;
	struct list_head states[N_STREAMS];
	struct {
		struct list_head states;
		void *base;
		size_t size;
		size_t off;
	} buf[N_BUFFERS];
	u64 payload;
	u64 endpoint;
	bool init_complete;
	int reached_hardware_boot;
	struct list_head rbufs;
	int rbuf_id;
	struct device *display_dev;
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
	if (!dcp->buf_va_size) {
		spin_unlock_irqrestore(&dcp->lock, flags);
		return;
	}

	if (!dcp->buf_va) {
		void *buf_va;
		dma_addr_t iova;

		spin_unlock_irqrestore(&dcp->lock, flags);
		buf_va = dma_alloc_coherent(dcp->rproc->dev.parent,
					    dcp->buf_va_size,
					    &iova, GFP_KERNEL);

		memset (buf_va, 0, dcp->buf_va_size);
		spin_lock_irqsave(&dcp->lock, flags);
		if (dcp->buf_va) {
			dma_free_coherent(dcp->rproc->dev.parent,
					  dcp->buf_va_size,
					  buf_va, iova);
		} else {
			struct apple_mbox_msg msg;
			msg.payload = 0;
			msg.endpoint = dcp->endpoint;

			msg.payload |= 0x0040;
			msg.payload |= iova << 16;
			msg.payload |= 0xfLL << 48;

			mbox_copy_and_send(dcp->chan, &msg);
			dcp->buf_va = buf_va;
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
		}
	}

	if (dcp->buf_va) {
		while (!list_empty(&dcp->buf[0].states) ||
		       !list_empty(&dcp->buf[1].states)) {
			printk("work func emptying\n");
			spin_unlock_irqrestore(&dcp->lock, flags);

			msleep(100);

			spin_lock_irqsave(&dcp->lock, flags);
		}
		if (list_empty(&dcp->buf[0].states) &&
		    list_empty(&dcp->buf[1].states)) {
			int bufno;
			printk("work func rewinding\n");
			for (bufno = 0; bufno < 1; bufno++) {
				dcp->buf[bufno].off = 0;
				memset(dcp->buf[bufno].base, 0, dcp->buf[bufno].size);
			}
		}
	}
	spin_unlock_irqrestore(&dcp->lock, flags);
	complete_all(&dcp->buffer_complete);
}

static void apple_dcp_tx_done(struct mbox_client *cl, void *msg,
			      int code)
{
	struct apple_dcp *dcp = container_of(cl, struct apple_dcp, cl);
	struct apple_mbox_msg *mbox = msg;
	unsigned stream = FIELD_GET(GENMASK(11,8), mbox->payload);
	stream = 0; // XXX
	mbox_chan_txdone(&dcp->downstream_chans[stream], code);
}

static void apple_dcp_work_hardware_boot_func(struct work_struct *work);

static void apple_dcp_work_map_physical_func(struct work_struct *work);

static void apple_dcp_work_map_buffer_func(struct work_struct *work);

static void apple_dcp_work_allocate_buffer_func(struct work_struct *work);

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
		unsigned ctx = FIELD_GET(GENMASK(11,8), payload);
		unsigned off = FIELD_GET(GENMASK(31,16), payload);
		int bufno;
		bool ack = payload & BIT(6);
		switch (ctx) {
		case 0:
			bufno = BUF_CALLBACK; break;
		case 2:
			bufno = BUF_COMMAND; break;
		case 3:
			bufno = BUF_ASYNC; break;
		}
		if (ack) /* response */ {
			struct apple_dcp_transaction_state *state =
				list_first_entry(&dcp->buf[bufno].states,
						 struct apple_dcp_transaction_state,
						 list);
			if (list_empty(&dcp->buf[bufno].states)) {
				WARN_ON(1);
			} else {
				memcpy(state->msg->dcp_data +
				       state->msg->dcp.len_input,
				       state->buf_base + state->buf_off +
				       state->msg->dcp.len_output + 12,
				       state->msg->dcp.len_output);
				complete_all(&state->complete);
				list_del(&state->list);
			}
			spin_unlock_irqrestore(&dcp->lock, flags);
			return;
		} else if (ctx == 0 && !ack) {
			unsigned msglen = FIELD_GET(GENMASK(63,32), payload);
			u32 fourcc = U32_FOURCC((u8 *)dcp->buf[bufno].base + off);
			u32 in_len = *(u32 *)((u8 *)dcp->buf[bufno].base + off + 4);
			u32 out_len = *(u32 *)((u8 *)dcp->buf[bufno].base + off + 8);
			struct apple_mbox_msg mbox;

			if (0) print_hex_dump(KERN_EMERG, "callback:", DUMP_PREFIX_OFFSET,
				       16, 1, dcp->buf[bufno].base + off, msglen > 256 ? 256 : msglen, true);
			if (fourcc == FOURCC("D598")) {
				mdelay(100);
			} else if (fourcc == FOURCC("D000") ||
				   fourcc == FOURCC("D001") ||
				   fourcc == FOURCC("D107") ||
				   fourcc == FOURCC("D108") ||
				   fourcc == FOURCC("D109") ||
				   fourcc == FOURCC("D110") ||
				   fourcc == FOURCC("D122") ||
				   fourcc == FOURCC("D123") ||
				   fourcc == FOURCC("D124") ||
				   fourcc == FOURCC("D206") ||
				   fourcc == FOURCC("D207") ||
				   fourcc == FOURCC("D413") ||
				   fourcc == FOURCC("D414") ||
				   fourcc == FOURCC("D415") ||
				   fourcc == FOURCC("D552") ||
				   fourcc == FOURCC("D561") ||
				   fourcc == FOURCC("D563") ||
				   fourcc == FOURCC("D565") ||
				   fourcc == FOURCC("D567")) {
				unsigned off1 = 12 + in_len;
				u32 data[] = { 1 };
				memcpy((u8*)dcp->buf[bufno].base + off + off1, data,
				       sizeof data);
			} else if (fourcc == FOURCC("D101") ||
				   fourcc == FOURCC("D111") ||
				   fourcc == FOURCC("D118") ||
				   fourcc == FOURCC("D574")) {
				unsigned off1 = 12 + in_len;
				u32 data[] = { 0 };
				memcpy((u8*)dcp->buf[bufno].base + off + off1, data,
				       sizeof data);
			} else if (fourcc == FOURCC("D120")) {
				/* read_edt_data */
				unsigned off1 = 12 + in_len;
				u32 data[9] = { 0x02, };
				memcpy((u8*)dcp->buf[bufno].base + off + off1, data,
				       sizeof data);
			} else if (fourcc == FOURCC("D401")) {
				/* sr_get_uint_prop */
				unsigned off1 = 12 + in_len;
				u32 data[10] = { 0, };
				memcpy((u8*)dcp->buf[bufno].base + off + off1, data,
				       sizeof data);
			} else if (fourcc == FOURCC("D411")) {
				/* sr_mapDeviceMemoryWithIndex */
				u32 data[10] = { 0x3b3d0000, 2, 0x4000, 0, };
				unsigned off1 = 12 + in_len;
				memcpy((u8*)dcp->buf[bufno].base + off + off1, data,
				       sizeof data);
			} else if (fourcc == FOURCC("D201")) {
				/* map_buffer */
				dcp->map_physical_buf = dcp->buf[bufno].base + off;
				INIT_WORK(&dcp->work_map_physical, apple_dcp_work_map_buffer_func);
				schedule_work(&dcp->work_map_physical);
				spin_unlock_irqrestore(&dcp->lock, flags);
				return;
			} else if (fourcc == FOURCC("D451")) {
				dcp->map_physical_buf = dcp->buf[bufno].base + off;
				INIT_WORK(&dcp->work_map_physical, apple_dcp_work_allocate_buffer_func);
				schedule_work(&dcp->work_map_physical);
				spin_unlock_irqrestore(&dcp->lock, flags);
				return;
			} else if (fourcc == FOURCC("D452")) {
				dcp->map_physical_buf = dcp->buf[bufno].base + off;
				INIT_WORK(&dcp->work_map_physical, apple_dcp_work_map_physical_func);
				schedule_work(&dcp->work_map_physical);
				spin_unlock_irqrestore(&dcp->lock, flags);
				return;
			} else if (fourcc == FOURCC("D003")) {
				/* rt_bandwidth_setup_ap */
				unsigned off1 = 12 + in_len;
				u32 data[16] = { 0, 0, 0x3b738014, 0x2, 0x3bc3c000, 0x2, 0, 2, };
				memcpy((u8*)dcp->buf[bufno].base + off + off1, data,
				       sizeof data);
			} else if (fourcc == FOURCC("D116")) {
				unsigned off1 = 12;
				u32 data[] = { 1 };
				printk(KERN_EMERG "reached hardware boot!\n");
				memcpy((u8*)dcp->buf[bufno].base + off + off1,
				       data, sizeof data);
				INIT_WORK(&dcp->work_hardware_boot, apple_dcp_work_hardware_boot_func);
				schedule_work(&dcp->work_hardware_boot);
				spin_unlock_irqrestore(&dcp->lock, flags);
				return;
			} else if (fourcc == FOURCC("D408")) {
				/* sr_get_uint_prop */
				unsigned off1 = 12 + in_len;
				u32 data[10] = { 533333328 };
				memcpy((u8*)dcp->buf[bufno].base + off + off1, data,
				       sizeof data);
			} else if (out_len != 0) {
				printk(KERN_EMERG "THAT'S WRONG\n");
			}

			if (0) print_hex_dump(KERN_EMERG, "response:", DUMP_PREFIX_OFFSET,
				       16, 1, dcp->buf[bufno].base + off + 12 + in_len, out_len, true);
			mbox.payload = 0x42;
			mbox.endpoint = dcp->endpoint;
			spin_unlock_irqrestore(&dcp->lock, flags);
			if (dcp->buf[bufno].base && 0)
				print_hex_dump(KERN_EMERG, "inbuf:", DUMP_PREFIX_OFFSET,
					       16, 1, dcp->buf[bufno].base, 256, true);
			mbox_copy_and_send(dcp->chan, &mbox);
		} else if (ctx == 3 && !ack) {
			unsigned msglen = FIELD_GET(GENMASK(63,32), payload);
			u32 fourcc = U32_FOURCC((u8 *)dcp->buf[bufno].base + off);
			u32 in_len = *(u32 *)((u8 *)dcp->buf[bufno].base + off + 4);
			u32 out_len = *(u32 *)((u8 *)dcp->buf[bufno].base + off + 8);
			struct apple_mbox_msg mbox;

			if (0)
			print_hex_dump(KERN_EMERG, "callback:", DUMP_PREFIX_OFFSET,
				       16, 1, dcp->buf[bufno].base + off, msglen > 256 ? 256 : msglen, true);
			if (fourcc == FOURCC("D598")) {
				mdelay(100);
			} else if (fourcc == FOURCC("D000") ||
				   fourcc == FOURCC("D001") ||
				   fourcc == FOURCC("D107") ||
				   fourcc == FOURCC("D108") ||
				   fourcc == FOURCC("D109") ||
				   fourcc == FOURCC("D110") ||
				   fourcc == FOURCC("D122") ||
				   fourcc == FOURCC("D123") ||
				   fourcc == FOURCC("D124") ||
				   fourcc == FOURCC("D206") ||
				   fourcc == FOURCC("D207") ||
				   fourcc == FOURCC("D413") ||
				   fourcc == FOURCC("D414") ||
				   fourcc == FOURCC("D415") ||
				   fourcc == FOURCC("D552") ||
				   fourcc == FOURCC("D561") ||
				   fourcc == FOURCC("D563") ||
				   fourcc == FOURCC("D565") ||
				   fourcc == FOURCC("D567")) {
				unsigned off1 = 12 + in_len;
				u32 data[] = { 1 };
				memcpy((u8*)dcp->buf[bufno].base + off + off1, data,
				       sizeof data);
			} else if (fourcc == FOURCC("D101") ||
				   fourcc == FOURCC("D111") ||
				   fourcc == FOURCC("D118") ||
				   fourcc == FOURCC("D574")) {
				unsigned off1 = 12 + in_len;
				u32 data[] = { 0 };
				memcpy((u8*)dcp->buf[bufno].base + off + off1, data,
				       sizeof data);
			} else if (fourcc == FOURCC("D120")) {
				/* read_edt_data */
				unsigned off1 = 12 + in_len;
				u32 data[9] = { 0x02, };
				memcpy((u8*)dcp->buf[bufno].base + off + off1, data,
				       sizeof data);
			} else if (fourcc == FOURCC("D401")) {
				/* sr_get_uint_prop */
				unsigned off1 = 12 + in_len;
				u32 data[10] = { 0, };
				memcpy((u8*)dcp->buf[bufno].base + off + off1, data,
				       sizeof data);
			} else if (fourcc == FOURCC("D408")) {
				/* sr_get_uint_prop */
				unsigned off1 = 12 + in_len;
				u32 data[10] = { 533333328 };
				memcpy((u8*)dcp->buf[bufno].base + off + off1, data,
				       sizeof data);
			} else if (fourcc == FOURCC("D208")) {
				/* sr_get_uint_prop */
				unsigned off1 = 12 + in_len;
				static int time = 1000;
				u32 data[10] = { time++, };
				memcpy((u8*)dcp->buf[bufno].base + off + off1, data,
				       sizeof data);
			} else if (fourcc == FOURCC("D411")) {
				/* sr_mapDeviceMemoryWithIndex */
				u32 data[10] = { 0x3b3d0000, 2, 0x4000, 0, };
				unsigned off1 = 12 + in_len;
				memcpy((u8*)dcp->buf[bufno].base + off + off1, data,
				       sizeof data);
			} else if (fourcc == FOURCC("D201")) {
				/* map_buffer */
				dcp->map_physical_buf = dcp->buf[bufno].base + off;
				INIT_WORK(&dcp->work_map_physical, apple_dcp_work_map_buffer_func);
				schedule_work(&dcp->work_map_physical);
				spin_unlock_irqrestore(&dcp->lock, flags);
				return;
			} else if (fourcc == FOURCC("D451")) {
				dcp->map_physical_buf = dcp->buf[bufno].base + off;
				INIT_WORK(&dcp->work_map_physical, apple_dcp_work_allocate_buffer_func);
				schedule_work(&dcp->work_map_physical);
				spin_unlock_irqrestore(&dcp->lock, flags);
				return;
			} else if (fourcc == FOURCC("D452")) {
				dcp->map_physical_buf = dcp->buf[bufno].base + off;
				INIT_WORK(&dcp->work_map_physical, apple_dcp_work_map_physical_func);
				schedule_work(&dcp->work_map_physical);
				spin_unlock_irqrestore(&dcp->lock, flags);
				return;
			} else if (fourcc == FOURCC("D003")) {
				/* rt_bandwidth_setup_ap */
				unsigned off1 = 12 + in_len;
				u32 data[16] = { 0, 0, 0x3b738014, 0x2, 0x3bc3c000, 0x2, 0, 2, };
				memcpy((u8*)dcp->buf[bufno].base + off + off1, data,
				       sizeof data);
			} else if (fourcc == FOURCC("D116")) {
				unsigned off1 = 12;
				u32 data[] = { 1 };
				printk(KERN_EMERG "reached hardware boot!\n");
				memcpy((u8*)dcp->buf[bufno].base + off + off1,
				       data, sizeof data);
				INIT_WORK(&dcp->work_hardware_boot, apple_dcp_work_hardware_boot_func);
				schedule_work(&dcp->work_hardware_boot);
				spin_unlock_irqrestore(&dcp->lock, flags);
				return;
			} else if (out_len != 0) {
				printk(KERN_EMERG "THAT'S WRONG\n");
			}

			if (0)
			print_hex_dump(KERN_EMERG, "response:", DUMP_PREFIX_OFFSET,
				       16, 1, dcp->buf[bufno].base + off + 12 + in_len, out_len, true);
			mbox.payload = 0x342;
			mbox.endpoint = dcp->endpoint;
			spin_unlock_irqrestore(&dcp->lock, flags);
			if (dcp->buf[bufno].base && 0)
				print_hex_dump(KERN_EMERG, "inbuf:", DUMP_PREFIX_OFFSET,
					       16, 1, dcp->buf[bufno].base, 256, true);
			mbox_copy_and_send(dcp->chan, &mbox);
		} else {
			dev_warn(dcp->dev, "unhandled message %016llx\n",
				 msg->payload);
			spin_unlock_irqrestore(&dcp->lock, flags);
		}
	} else if (type == 0) {
		dev_warn(dcp->dev, "unhandled message %016llx\n",
			 msg->payload);
		spin_unlock_irqrestore(&dcp->lock, flags);
	} else {
		dev_warn(dcp->dev, "unhandled message %016llx\n",
			 msg->payload);
		spin_unlock_irqrestore(&dcp->lock, flags);
	}
}

int apple_dcp_reached_hardware_boot(struct mbox_chan *chan, struct device *dev)
{
	struct apple_dcp *dcp = chan->con_priv;
	dcp->display_dev = dev;
	return dcp->reached_hardware_boot;
}
EXPORT_SYMBOL(apple_dcp_reached_hardware_boot);

struct apple_dcp_transaction_state *apple_dcp_transaction_state(struct mbox_chan *chan, struct apple_dcp_mbox_msg *msg, struct apple_dcp_msg_header *header, void *data, u64 payload, int bufno)
{
	struct apple_dcp *dcp = chan->con_priv;
	size_t dcp_msg_size = apple_dcp_msg_size(header);
	struct apple_dcp_transaction_state *state =
		devm_kzalloc(dcp->dev, sizeof *state, GFP_KERNEL);
	unsigned long flags;
	size_t offset;
	struct apple_mbox_msg mbox;

	if (0)
	print_hex_dump(KERN_EMERG, "tx pre:", DUMP_PREFIX_OFFSET,
		       16, 1, header, dcp_msg_size, true);

	if (!state)
		return ERR_PTR(-ENOMEM);

	init_completion(&state->complete);

  again:
	spin_lock_irqsave(&dcp->lock, flags);

	if (!dcp->init_complete)
		goto wait_retry;

	if (dcp->buf_va == NULL)
		goto schedule_wait_retry;

	bufno = 0;
	offset = dcp->buf[bufno].off;

	if (dcp->buf[bufno].off + dcp_msg_size > dcp->buf[bufno].size) {
		goto schedule_wait_retry;
	}

	memset(dcp->buf[bufno].base + dcp->buf[bufno].off, 0, round_up(dcp_msg_size, 0x40));
	memcpy(dcp->buf[bufno].base + dcp->buf[bufno].off, header, sizeof(*header));
	dcp->buf[bufno].off += sizeof(*header);
	memcpy(dcp->buf[bufno].base + dcp->buf[bufno].off, data, header->len_input);
	dcp->buf[bufno].off += header->len_input;
	memset(dcp->buf[bufno].base + dcp->buf[bufno].off, 0, header->len_output);
	dcp->buf[bufno].off += header->len_output;
	dcp->buf[bufno].off = round_up(dcp->buf[bufno].off, 0x40);

	state->msg = msg;
	state->buf_base = dcp->buf[bufno].base;
	state->buf_off = offset;

	mbox.payload = payload & 0xffff;
	mbox.payload |= offset << 16;
	mbox.payload |= dcp_msg_size << 32;
	mbox.endpoint = dcp->endpoint;
	bufno = (msg->mbox.payload & 0x200) ? 0 : 1;
	list_add(&state->list, &dcp->buf[bufno].states);
	if (dcp->buf[bufno].base && 0)
		print_hex_dump(KERN_EMERG, "inbuf:", DUMP_PREFIX_OFFSET,
			       16, 1, dcp->buf[bufno].base, 256, true);
	mbox_send_message(dcp->chan, &mbox);
	spin_unlock_irqrestore(&dcp->lock, flags);
	return state;

  schedule_wait_retry:
	reinit_completion(&dcp->buffer_complete);
	INIT_WORK(&dcp->work, apple_dcp_work_func);
	schedule_work(&dcp->work);
  wait_retry:
	spin_unlock_irqrestore(&dcp->lock, flags);
	wait_for_completion(&dcp->buffer_complete);
	goto again;
}

int apple_dcp_msg_2(struct mbox_chan *chan, struct apple_dcp_msg *msg)
{
	struct apple_dcp *dcp = chan->con_priv;
	u64 payload = 0;
	switch (chan - dcp->downstream_chans) {
	case STREAM_COMMAND:
		payload = 0x202;
		break;
	case STREAM_NESTED_COMMAND:
		payload = 0x002;
		break;
	case STREAM_CALLBACK:
		payload = 0x042;
		break;
	case STREAM_ASYNC:
		payload = 0x342;
		break;
	}
	int bufno = 0;
	struct apple_dcp_transaction_state *state =
		apple_dcp_transaction_state(chan, (void *)msg, &msg->header,
					    &msg->data, payload, bufno);
	unsigned long flags;
	return 0;
}

int apple_dcp_msg(struct mbox_chan *chan, struct apple_dcp_mbox_msg *msg)
{
	struct apple_dcp *dcp = chan->con_priv;
	size_t dcp_msg_size = apple_dcp_msg_size(&msg->dcp);
	u64 payload = msg->mbox.payload;
	int bufno = 0;
	struct apple_dcp_transaction_state *state =
		apple_dcp_transaction_state(chan, msg, &msg->dcp, &msg->dcp_data, payload, bufno);
	unsigned long flags;

	if (IS_ERR(state))
		return PTR_ERR(state);

	wait_for_completion(&state->complete);

	memcpy(msg->dcp_data + msg->dcp.len_input,
	       state->buf_base + state->buf_off + msg->dcp.len_input + 12,
	       msg->dcp.len_output);

#if 1
	spin_lock_irqsave(&dcp->lock, flags);
	if (dcp->buf[bufno].off == round_up(state->buf_off + dcp_msg_size,
					    0x40))
		dcp->buf[bufno].off = state->buf_off;
	spin_unlock_irqrestore(&dcp->lock, flags);
#endif

	if (0)
	print_hex_dump(KERN_EMERG, "tx post:", DUMP_PREFIX_OFFSET,
		       16, 1, &msg->dcp, dcp_msg_size, true);
	devm_kfree(dcp->dev, state);

	if (dcp->buf[bufno].base && 0)
		print_hex_dump(KERN_EMERG, "inbuf:", DUMP_PREFIX_OFFSET,
			       16, 1, dcp->buf[bufno].base, 256, true);
	return 0;
}

int apple_dcp_transaction(struct mbox_chan *chan,
			  struct apple_dcp_mbox_msg *msg)
{
	return apple_dcp_msg(chan, msg);
}
EXPORT_SYMBOL(apple_dcp_transaction);

static void apple_dcp_work_map_physical_func(struct work_struct *work)
{
	struct apple_dcp *dcp = container_of(work, struct apple_dcp, work_map_physical);
	void *ptr = dcp->map_physical_buf;
	phys_addr_t pa =
		(*((u32 *)(ptr + 12)) +
		 ((u64)*((u32 *)(ptr + 16)) << 32));
	u64 size =
		(*((u32 *)(ptr + 20)) +
		 ((u64)*((u32 *)(ptr + 24)) << 32));
	void *temp_buffer;
	dma_addr_t dma_addr;
	struct iommu_domain *domain;
	u32 in_len = *(u32 *)((u8 *)(ptr + 4));
	u32 out_len = *(u32 *)((u8 *)(ptr + 8));
	unsigned off1 = 12 + in_len;
	u32 data[10] = { 0x3b3d0000, 0x2, 0x4000, 0x00, };
	static u64 static_address = 0x30000000;
	struct apple_mbox_msg mbox;
	/* map_physical */
	printk("map_physical\n");
	mdelay(100);
	printk("dsmac %d\n",
	       dma_set_mask_and_coherent(dcp->rproc->dev.parent,
					 DMA_BIT_MASK(32)));
	domain = iommu_domain_alloc(dcp->dev->bus);
	mdelay(100);
	printk("pa %016llx size %016llx\n",
	       pa, size);
	mdelay(100);
	size = round_up(size, 16384);
	temp_buffer = dma_alloc_noncoherent(dcp->rproc->dev.parent, size, &dma_addr,
					    DMA_TO_DEVICE, GFP_KERNEL);
	printk("temp_buffer %p dma_addr %016llx\n",
	       temp_buffer, dma_addr);
	mdelay(100);
	dma_free_noncoherent(dcp->rproc->dev.parent, size, temp_buffer, dma_addr,
			     DMA_TO_DEVICE);
	printk("domain %p\n", domain);
	mdelay(100);
	iommu_attach_device(domain, dcp->rproc->dev.parent);
	dma_addr = static_address;
	iommu_map(domain, dma_addr, pa, size, IOMMU_READ|IOMMU_WRITE);
	data[0] = dma_addr;
	data[1] = (dma_addr>>32);
	data[2] = size;
	data[3] = 0;
	data[4] = ++dcp->rbuf_id;
	memcpy((u8*)ptr + off1, data, sizeof data);
	if (0)
	print_hex_dump(KERN_EMERG, "response:", DUMP_PREFIX_OFFSET,
		       16, 1, ptr + 12 + in_len, out_len, true);
	mdelay(100);
	mbox.payload = 0x42;
	mbox.endpoint = dcp->endpoint;
	int bufno = BUF_CALLBACK;
	if (dcp->buf[bufno].base && 0)
		print_hex_dump(KERN_EMERG, "inbuf:", DUMP_PREFIX_OFFSET,
			       16, 1, dcp->buf[bufno].base, 256, true);
	mbox_copy_and_send(dcp->chan, &mbox);
	static_address += size;
}

static void init_buffer(struct apple_dcp *dcp)
{
	struct iommu_domain *domain = iommu_domain_alloc(dcp->display_dev->bus);
	iommu_attach_device(domain, dcp->display_dev);
	iommu_map(domain, 0xa0000000, 0x900000000, 32<<20, IOMMU_READ|IOMMU_WRITE);
	*(u64 *)phys_to_virt(0x9fff78280) =
		*(u64 *)phys_to_virt(0x9fff48280);
}

static void apple_dcp_work_map_buffer_func(struct work_struct *work)
{
	struct apple_dcp *dcp = container_of(work, struct apple_dcp, work_map_physical);
	static u64 static_addr = 0xc0000000;
	void *ptr = dcp->map_physical_buf;
	struct apple_mbox_msg mbox;
	struct {
		struct apple_dcp_msg_header header;
		struct {
			u32 bufid;
			u64 unk;
		} __attribute__((packed)) in;
		struct {
			u64 vaddr;
			u64 dva;
			u32 unk;
		} __attribute__((packed)) out;
	} __attribute__((packed)) *m = ptr;
	u64 size;
	void *temp_buffer;
	dma_addr_t dma_addr;
	struct iommu_domain *domain = iommu_domain_alloc(dcp->display_dev->bus);
	u32 in_len = *(u32 *)((u8 *)(ptr + 4));
	u32 out_len = *(u32 *)((u8 *)(ptr + 8));
	void *va;
	struct apple_dcp_remote_buffer *rbuf;
	list_for_each_entry(rbuf, &dcp->rbufs, list) {
		if (rbuf->id == m->in.bufid)
			break;
	}
	if (list_entry_is_head(rbuf, &dcp->rbufs, list)) {
		printk("not found!\n");
		return;
	}
	/* map_buffer */
	printk("map_buffer\n");
	m->out.vaddr = 0;
	m->out.unk = 0;
	mdelay(100);
	mdelay(100);
	size = round_up(rbuf->size, 16384);
	mdelay(100);
	rbuf->dva = static_addr;
	iommu_attach_device(domain, dcp->dev);
	printk("domain %p\n", domain);
	mdelay(100);
	for (va = rbuf->va; va < rbuf->va + rbuf->size; va += 16384) {
		iommu_map(domain, rbuf->dva + (va - rbuf->va),
			  virt_to_phys(va), 16384, IOMMU_READ|IOMMU_WRITE);
	}
	m->out.dva = rbuf->dva;
	if (0)
	print_hex_dump(KERN_EMERG, "response:", DUMP_PREFIX_OFFSET,
		       16, 1, ptr + 12 + in_len, out_len, true);
	mdelay(100);
	mbox.payload = 0x42;
	mbox.endpoint = dcp->endpoint;
	int bufno = BUF_CALLBACK;
	if (dcp->buf[bufno].base && 0)
		print_hex_dump(KERN_EMERG, "inbuf:", DUMP_PREFIX_OFFSET,
			       16, 1, dcp->buf[bufno].base, 256, true);
	static_addr += size;
	mbox_copy_and_send(dcp->chan, &mbox);
}


static void apple_dcp_work_allocate_buffer_func(struct work_struct *work)
{
	struct apple_dcp *dcp = container_of(work, struct apple_dcp, work_map_physical);
	void *ptr = dcp->map_physical_buf;
	struct {
		struct apple_dcp_msg_header header;
		struct {
			u32 unk0;
			u64 size;
			u64 unk1;
		} __attribute__((packed)) in;
		struct {
			u64 paddr;
			u64 dva;
			u64 dvasize;
			u32 mapid;
		} __attribute__((packed)) out;
	} __attribute__((packed)) *m = ptr;
	struct apple_dcp_remote_buffer *rbuf = kzalloc(sizeof *rbuf, GFP_KERNEL);
	u64 size = m->in.size;
	void *temp_buffer;
	dma_addr_t dma_addr;
	u32 in_len = *(u32 *)((u8 *)(ptr + 4));
	u32 out_len = *(u32 *)((u8 *)(ptr + 8));
	struct apple_mbox_msg mbox;
	printk("allocate_buffer\n");
	list_add(&rbuf->list, &dcp->rbufs);
	rbuf->id = ++dcp->rbuf_id;
	mdelay(100);
	size = round_up(size, 16384);
	dma_set_mask_and_coherent(dcp->dev, DMA_BIT_MASK(32));
	temp_buffer = dma_alloc_coherent(dcp->dev, size, &dma_addr,
					 GFP_KERNEL);
	rbuf->dva = dma_addr;
	rbuf->size = size;
	rbuf->va = temp_buffer;
	m->out.paddr = 0; // virt_to_phys(temp_buffer);
	m->out.mapid = rbuf->id;
	m->out.dva = dma_addr;
	m->out.dvasize = round_up(size, 16384);
	printk("temp_buffer %p dma_addr %016llx\n",
	       temp_buffer, dma_addr);
	mdelay(100);
	if (0)
	print_hex_dump(KERN_EMERG, "response:", DUMP_PREFIX_OFFSET,
		       16, 1, ptr + 12 + in_len, out_len, true);
	mdelay(100);
	mbox.payload = 0x42;
	mbox.endpoint = dcp->endpoint;
	int bufno = BUF_CALLBACK;
	if (dcp->buf[bufno].base && 0)
		print_hex_dump(KERN_EMERG, "inbuf:", DUMP_PREFIX_OFFSET,
			       16, 1, dcp->buf[bufno].base, 256, true);
	mbox_copy_and_send(dcp->chan, &mbox);
}


static void apple_dcp_work_hardware_boot_func(struct work_struct *work)
{
	struct apple_dcp *dcp = container_of(work, struct apple_dcp, work_hardware_boot);
	struct apple_dcp_mbox_msg *msg = kzalloc(1024*1024, GFP_KERNEL);
	u32 data[2] = { 6, };
	u32 update_notify_clients_dcp_data[] = {
		0,0,0,0,0,0,1,1,1,0,1,1,1,
	};
	/* A407: swap_start(swapid, io_user_client) */
	struct apple_dcp_io_user_client {
		struct {
			u32 unk0;
			u64 addr; /* an unhashed kernel VA, apparently? */
			u64 flags;
			u32 unk1;
		} __attribute__((packed)) in;
		struct {
			u32 swapid;
			u32 unk0;
			u64 unk[2];
		} __attribute__((packed)) out;
	} io_user_client = {
		{
			0,
			0xFFFFFE1667BA4A00,
			0x0000010000000000,
		},
		{ },
	};
#define MAX_PLANES 3
	u32 swapid;
	u32 surface_id = 3;
	struct apple_swap_rect {
		u32 x, y, width, height;
	} __attribute__((packed));
	struct apple_plane_info {
		u32 width;
		u32 height;
		u32 base;
		u32 offset;
		u32 stride;
		u32 size;
		u16 tile_size;
		u8 tile_width;
		u8 tile_height;
		u8 unk[0xd];
		u8 unk2;
		u8 unk3[0x26];
	} __attribute__((packed));
	struct apple_swap_submit_dcp {
		struct apple_swaprec {
			u32 unk_mbz0[16];
			u32 flags[4];
			u32 swap_id;
			u32 surf_ids[4];
			struct apple_swap_rect src_rect[4];
			u32 surf_flags[4];
			u32 surf_unk[4];
			struct apple_swap_rect dst_rect[4];
			u32 swap_enabled;
			u32 swap_completed;
			u32 unk_mbz1[(0x1b8 + 0x14 + 0x3c + 12)/4];
		} __attribute__((packed)) swaprec;
		struct apple_surface {
			u8 is_tiled;
			u8 unk0[2];
			u32 plane_cnt[2];
			u32 format;
			u32 unk1;
			u8 unk2[2];
			u32 stride;
			u16 pix_size;
			u8 pel_w;
			u8 pel_h;
			u32 offset;
			u32 width;
			u32 height;
			u32 buf_size;
			u32 unk5[2];
			u32 surface_id;
			u8 comp_types[MAX_PLANES * 8];
			u64 has_comp;
			struct apple_plane_info planes[MAX_PLANES];
			u64 has_planes;
			u8 compression_info[MAX_PLANES * 0x34];
			u64 has_compression_info;
			u32 unk3[2];
			u8 unk4[7];
		} __attribute__((packed)) surfaces[4];
		u64 surf_addr[4];
		u8 unk_bool;
		u64 unk_float;
		u32 unk_int;
		u32 unk_flags;
	} __attribute__((packed));
	struct apple_swap_submit_dcp *swap_submit = kzalloc(sizeof *swap_submit, GFP_KERNEL);
	u32 powerstate_data[] = { 1, 0, 0 };

	msg->mbox.payload = 0x2;
	msg->mbox.endpoint = dcp->endpoint;

	printk("booting hardware\n");
	/* A357: set_create_DFB() */
	msg->dcp.code = FOURCC("A357");
	msg->dcp.len_input = 0;
	msg->dcp.len_output = 0;
	apple_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);

	msleep(1000);
	/* A443: do_create_default_frame_buffer() */
	msg->dcp.code = FOURCC("A443");
	msg->dcp.len_input = 0;
	msg->dcp.len_output = 4;
	apple_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);

	msleep(1000);
	/* A029: setup_video_limits() */
	msg->dcp.code = FOURCC("A029");
	msg->dcp.len_input = 0;
	msg->dcp.len_output = 0;
	apple_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);

	msleep(1000);
	/* A463: flush_supportsPower(true) */
	msg->dcp.code = FOURCC("A463");
	msg->dcp.len_input = 4;
	msg->dcp_data[0] = 1;
	msg->dcp_data[1] = 0;
	msg->dcp_data[2] = 0;
	msg->dcp_data[3] = 0;
	msg->dcp.len_output = 0;
	apple_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);
	msg->dcp_data[0] = 0;
	msleep(1000);

#if 0
	/* A000: late_init_signal() */
	msg->dcp.code = FOURCC("A000");
	msg->dcp.len_input = 0;
	msg->dcp.len_output = 4;
	apple_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);
#endif
	

	/* A460: setDisplayRefreshProperties() */
	msg->dcp.code = FOURCC("A460");
	msg->dcp.len_input = 0;
	msg->dcp.len_output = 4;
	apple_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);

	msg->mbox.payload = 0x42;
	mbox_copy_and_send(dcp->chan, &msg->mbox);

	msg->mbox.payload = 0x202;

	while (!list_empty(&dcp->buf[0].states))
		msleep(100);

	/* A426: get_color_remap_mode(6) */
	msg->dcp.code = FOURCC("A426");
	msg->dcp.len_input = 8;
	msg->dcp.len_output = 8;
	memcpy(msg->dcp_data, data, sizeof(data));
	apple_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);

	/* A447: enable_disable_video_power_savings(0) */
	msg->dcp.code = FOURCC("A447");
	msg->dcp.len_input = 4;
	msg->dcp.len_output = 4;
	memset(msg->dcp_data, 0, 4);
	apple_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);

	/* A034: update_notify_clients_dcp([...]) */
	msg->dcp.code = FOURCC("A034");
	msg->dcp.len_input = 0x34;
	msg->dcp.len_output = 0;
	memcpy(msg->dcp_data, update_notify_clients_dcp_data, sizeof(update_notify_clients_dcp_data));
	apple_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);

	/* A454: first_client_open() */
	msg->dcp.code = FOURCC("A454");
	msg->dcp.len_input = 0;
	msg->dcp.len_output = 0;
	apple_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);

	msg->dcp.code = FOURCC("A469");
	msg->dcp.len_input = 0;
	msg->dcp.len_output = 4;
	apple_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);

	msg->dcp.code = FOURCC("A411");
	msg->dcp.len_input = 0;
	msg->dcp.len_output = 4;
	apple_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);

	if (0){
		/* A468: setPowerState(1, 0, 0) */
		msg->dcp.code = FOURCC("A468");
		msg->dcp.len_input = 12;
		msg->dcp.len_output = 8;
		memcpy(msg->dcp_data, powerstate_data, 12);
		apple_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);
	}

	msleep(1000);
	{
		/* A468: setPowerState(1, 0, 0) */
		msg->dcp.code = FOURCC("A468");
		msg->dcp.len_input = 12;
		msg->dcp.len_output = 8;
		memcpy(msg->dcp_data, powerstate_data, 12);
		apple_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);
	}

	{
		/* A412: setDigitalMode(0x59, 0x43) */
		const u32 mode_args[] = { 0x59, 0x43 };
		msg->dcp.code = FOURCC("A412");
		msg->dcp.len_input = 8;
		msg->dcp.len_output = 4;
		memcpy(msg->dcp_data, mode_args, sizeof(mode_args));
		apple_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);
	}

#if 0
	/* A000: late_init_signal() */
	msg->dcp.code = FOURCC("A000");
	msg->dcp.len_input = 0;
	msg->dcp.len_output = 4;
	apple_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);
#endif

	init_buffer(dcp);
	u32 delay = 2000;
	while (1) {
	msg->dcp.code = FOURCC("A407");
	msg->dcp.len_input = sizeof(io_user_client.in);
	msg->dcp.len_output = sizeof(io_user_client.out);
	memcpy(msg->dcp_data, &io_user_client, sizeof(io_user_client));
	apple_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);
	memcpy(&io_user_client, msg->dcp_data, sizeof(io_user_client));
	swapid = io_user_client.out.swapid;
	printk("swapid 0x%x\n", swapid);
	if (1) {
		/* A412: setDigitalMode(0x59, 0x43) */
		const u32 mode_args[] = { 0x59, 0x43 };
		msg->dcp.code = FOURCC("A412");
		msg->dcp.len_input = 8;
		msg->dcp.len_output = 4;
		memcpy(msg->dcp_data, mode_args, sizeof(mode_args));
		apple_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);
	}
	msleep(delay); delay += 500;
	printk("%zd == 80?\n", sizeof(struct apple_plane_info));
	printk("total size: %d\n", (int)sizeof(struct apple_swap_submit_dcp));
	printk("swaprec: %d == 800\n", (int)sizeof(struct apple_swaprec));
	printk("surface: %d == 516\n", (int)sizeof(struct apple_surface));
	swap_submit->swaprec.flags[0] = 0x861202;
	swap_submit->swaprec.flags[2] = 0x04;
	swap_submit->swaprec.swap_id = swapid;
	swap_submit->swaprec.surf_ids[0] = surface_id;
	swap_submit->swaprec.src_rect[0].width = 3840;
	swap_submit->swaprec.src_rect[0].height = 2160;
#if 0
	swap_submit->swaprec.src_rect[1].width = 3840;
	swap_submit->swaprec.src_rect[1].height = 2160;
	swap_submit->swaprec.src_rect[2].width = 3840;
	swap_submit->swaprec.src_rect[2].height = 2160;
	swap_submit->swaprec.src_rect[3].width = 3840;
	swap_submit->swaprec.src_rect[3].height = 2160;
#endif
	swap_submit->swaprec.surf_flags[0] = 1;
	swap_submit->swaprec.dst_rect[0].width = 3840;
	swap_submit->swaprec.dst_rect[0].height = 2160;
#if 0
	swap_submit->swaprec.dst_rect[1].width = 3840;
	swap_submit->swaprec.dst_rect[1].height = 2160;
	swap_submit->swaprec.dst_rect[2].width = 3840;
	swap_submit->swaprec.dst_rect[2].height = 2160;
	swap_submit->swaprec.dst_rect[3].width = 3840;
	swap_submit->swaprec.dst_rect[3].height = 2160;
#endif
	swap_submit->swaprec.swap_enabled = 0x80000007;
	swap_submit->swaprec.swap_completed = 0x80000007;
	swap_submit->surf_addr[0] = 0xa0000000;
	swap_submit->surfaces[0].format = 0x42475241;
	swap_submit->surfaces[0].unk2[0] = 0x0d;
	swap_submit->surfaces[0].unk2[1] = 0x01;
	swap_submit->surfaces[0].stride = 3840 * 4;
	swap_submit->surfaces[0].pix_size = 4;
	swap_submit->surfaces[0].pel_w = 1;
	swap_submit->surfaces[0].pel_h = 1;
	swap_submit->surfaces[0].width = 3840;
	swap_submit->surfaces[0].height = 2160;
	swap_submit->surfaces[0].buf_size = 3840 * 2160 * 4;
	swap_submit->surfaces[0].surface_id = surface_id;
	swap_submit->surfaces[0].has_comp = 1;
	swap_submit->surfaces[0].has_planes = 1;
	//print_hex_dump(KERN_EMERG, "swaprec:", DUMP_PREFIX_OFFSET, 16, 1, swap_submit, sizeof(*swap_submit), true);
	/* swap_submit_dcp */
	/* A408: swap_submit_dcp(swap_rec, surfaces, surfaddr, false, .0, 0) */
	msg->dcp.code = FOURCC("A408");
	msg->dcp.len_input = 0xb64; // sizeof(swapid) + sizeof(swap_submit);
	msg->dcp.len_output = 8;
	memcpy(msg->dcp_data, swap_submit, sizeof(*swap_submit));
	memset((void *)(&msg->dcp) + 0x475, 1, 1);
	memset((void *)(&msg->dcp) + 0xb6b, 1, 3);
	apple_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);
	{
		/* A412: setDigitalMode(0x59, 0x43) */
		const u32 mode_args[] = { 0x59, 0x43 };
		msg->dcp.code = FOURCC("A412");
		msg->dcp.len_input = 8;
		msg->dcp.len_output = 4;
		memcpy(msg->dcp_data, mode_args, sizeof(mode_args));
		apple_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);
	}
	msleep(30000);
	}
#if 0
	/* A000: late_init_signal() */
	msg->dcp.code = FOURCC("A000");
	msg->dcp.len_input = 0;
	msg->dcp.len_output = 4;
	apple_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);
#endif
	if (0) {

		/* A412: setDigitalMode(0x59, 0x43) */
		const u32 mode_args[] = { 0x59, 0x43 };
		msg->dcp.code = FOURCC("A412");
		msg->dcp.len_input = 8;
		msg->dcp.len_output = 4;
		memcpy(msg->dcp_data, mode_args, sizeof(mode_args));
		apple_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);
		msleep(10000);
	}

	dcp->reached_hardware_boot = 1;
	return;
}

static int apple_dcp_send_data(struct mbox_chan *chan, void *msg_header)
{
	struct apple_dcp *dcp = chan->con_priv;
	switch (chan - dcp->downstream_chans) {
	case STREAM_COMMAND:
		return apple_dcp_msg(chan, msg_header);
	}
	BUG_ON(1);
}

static struct mbox_chan_ops apple_dcp_mbox_chan_ops = {
	.send_data = apple_dcp_send_data,
};

static int apple_dcp_probe(struct platform_device *pdev)
{
	struct apple_dcp *dcp;
	int ret;
	u32 endpoint;
	int i;

	dcp = devm_kzalloc(&pdev->dev, sizeof *dcp, GFP_KERNEL);
	if (!dcp)
		return -ENOMEM;

	dcp->dev = &pdev->dev;
	dcp->buf_va_size = 0x200000;
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

	INIT_LIST_HEAD(&dcp->rbufs);
	for (i = 0; i < N_BUFFERS; i++)
		INIT_LIST_HEAD(&dcp->buf[i].states);
	for (i = 0; i < N_STREAMS; i++)
		dcp->downstream_chans[i].con_priv = dcp;

	dcp->mbox_controller.dev = dcp->dev;
	dcp->mbox_controller.ops = &apple_dcp_mbox_chan_ops;
	dcp->mbox_controller.chans = dcp->downstream_chans;
	dcp->mbox_controller.num_chans = N_STREAMS;
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
