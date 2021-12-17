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
#include <linux/platform_device.h>
#include <linux/remoteproc.h>
#include <linux/slab.h>

struct apple_asc_dcp_remote_buffer {
	struct list_head list;
	u32 id;
	u64 dva;
	void *va;
	u64 size;
};

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
	int reached_hardware_boot;
	struct list_head rbufs;
	struct list_head shmem_messages;
	int rbuf_id;
	struct device *display_dev;
};

/* XXX prototype for debugging */
static int apple_dcp_send_data(struct mbox_chan *chan, void *msg_header);

static void apple_dcp_msg_print(struct apple_dcp_msg *msg)
{
	printk("message %c%c%c%c, %d/%d\n",
	       (msg->header.code>>24) & 255,
	       (msg->header.code>>16) & 255,
	       (msg->header.code>>8) & 255,
	       msg->header.code & 255,
	       (int)msg->header.len_input,
	       (int)msg->header.len_output);

	print_hex_dump(KERN_EMERG, "H:", DUMP_PREFIX_OFFSET, 16, 1, msg->data-12, 12, true);
	print_hex_dump(KERN_EMERG, "I:", DUMP_PREFIX_OFFSET, 16, 1, msg->data, msg->header.len_input, true);
	print_hex_dump(KERN_EMERG, "O:", DUMP_PREFIX_OFFSET, 16, 1, msg->data + msg->header.len_input, msg->header.len_output, true);
	//print_hex_dump(KERN_EMERG, "C:", DUMP_PREFIX_OFFSET, 16, 1, msg->data - 12, msg->header.len_input + msg->header.len_output + 12, true);
}

static void apple_asc_dcp_flush_func(struct work_struct *work)
{
	struct apple_asc_dcp *dcp = container_of(work, struct apple_asc_dcp,
						 work);
	unsigned long flags;

	spin_lock_irqsave(&dcp->lock, flags);
	BUG_ON(!dcp->buf_va);

	while (true) {
		int bufno;
		while (!list_empty(&dcp->shmem_messages)) {
			spin_unlock_irqrestore(&dcp->lock, flags);
			msleep(100);
			spin_lock_irqsave(&dcp->lock, flags);
		}
		bufno = BUF_COMMAND;
		dcp->buf[bufno].off = 0;
		memset(dcp->buf[bufno].base, 0, dcp->buf[bufno].size);
		break;
	}
	spin_unlock_irqrestore(&dcp->lock, flags);
}

static void apple_asc_dcp_tx_done(struct mbox_client *cl, void *mbox_msg,
			      int code)
{
	struct apple_asc_dcp *dcp = container_of(cl, struct apple_asc_dcp, cl);
	struct apple_mbox_msg *mbox = mbox_msg;
	u64 payload = mbox->payload;
	bool ack = payload & BIT(6);
	unsigned ctx = FIELD_GET(GENMASK(11,  8), payload);
	int stream;
	unsigned type = FIELD_GET(GENMASK(3, 0), payload);

	if (type == 2) {
		switch (ctx) {
		case 0:
			stream = ack ? STREAM_CALLBACK : STREAM_NESTED_COMMAND;
			break;
		case 2:
			BUG_ON(ack);
			stream = STREAM_COMMAND;
			break;
		case 3:
			BUG_ON(!ack);
			stream = STREAM_ASYNC;
			break;

		default:
			BUG();
		}

		mbox_chan_txdone(&dcp->downstream_chans[stream], code);
	}

	kfree(mbox_msg);
}

static void apple_asc_dcp_work_hardware_boot_func(struct work_struct *work);

static void apple_asc_dcp_work_map_physical_func(struct work_struct *work);

static void apple_asc_dcp_work_map_buffer_func(struct work_struct *work);

static void apple_asc_dcp_work_allocate_buffer_func(struct work_struct *work);

#if 0
{
	if (type == 1) {
		dev_info(dcp->dev, "init complete\n");
		spin_unlock_irqrestore(&dcp->lock, flags);
	} else if (type == 2) {
		int bufno;
		switch (ctx) {
		case 0:
			bufno = BUF_CALLBACK; break;
		case 2:
			bufno = BUF_COMMAND; break;
		case 3:
			bufno = BUF_ASYNC; break;
		}
		if (ack) /* response */ {
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
				INIT_WORK(&dcp->work_map_physical, apple_asc_dcp_work_map_buffer_func);
				schedule_work(&dcp->work_map_physical);
				spin_unlock_irqrestore(&dcp->lock, flags);
				return;
			} else if (fourcc == FOURCC("D451")) {
				dcp->map_physical_buf = dcp->buf[bufno].base + off;
				INIT_WORK(&dcp->work_map_physical, apple_asc_dcp_work_allocate_buffer_func);
				schedule_work(&dcp->work_map_physical);
				spin_unlock_irqrestore(&dcp->lock, flags);
				return;
			} else if (fourcc == FOURCC("D452")) {
				dcp->map_physical_buf = dcp->buf[bufno].base + off;
				INIT_WORK(&dcp->work_map_physical, apple_asc_dcp_work_map_physical_func);
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
				INIT_WORK(&dcp->work_hardware_boot, apple_asc_dcp_work_hardware_boot_func);
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
				INIT_WORK(&dcp->work_map_physical, apple_asc_dcp_work_map_buffer_func);
				schedule_work(&dcp->work_map_physical);
				spin_unlock_irqrestore(&dcp->lock, flags);
				return;
			} else if (fourcc == FOURCC("D451")) {
				dcp->map_physical_buf = dcp->buf[bufno].base + off;
				INIT_WORK(&dcp->work_map_physical, apple_asc_dcp_work_allocate_buffer_func);
				schedule_work(&dcp->work_map_physical);
				spin_unlock_irqrestore(&dcp->lock, flags);
				return;
			} else if (fourcc == FOURCC("D452")) {
				dcp->map_physical_buf = dcp->buf[bufno].base + off;
				INIT_WORK(&dcp->work_map_physical, apple_asc_dcp_work_map_physical_func);
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
				INIT_WORK(&dcp->work_hardware_boot, apple_asc_dcp_work_hardware_boot_func);
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
	spin_unlock_irqrestore(&dcp->lock, flags);
	return;

unexpected:
	spin_unlock_irqrestore(&dcp->lock, flags);
	dev_warn(dcp->dev, "unexpected message %016llx\n",
		 msg->payload);
}
#endif

int apple_asc_dcp_reached_hardware_boot(struct mbox_chan *chan, struct device *dev)
{
	struct apple_asc_dcp *dcp = chan->con_priv;
	dcp->display_dev = dev;
	return dcp->reached_hardware_boot;
}
EXPORT_SYMBOL(apple_asc_dcp_reached_hardware_boot);

static void apple_asc_dcp_work_map_physical_func(struct work_struct *work)
{
	struct apple_asc_dcp *dcp = container_of(work, struct apple_asc_dcp, work_map_physical);
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
	printk("dsmac %d\n",
	       dma_set_mask_and_coherent(dcp->rproc->dev.parent,
					 DMA_BIT_MASK(32)));
	domain = iommu_domain_alloc(dcp->dev->bus);
	mdelay(100);
	mdelay(100);
	size = round_up(size, 16384);
	temp_buffer = dma_alloc_noncoherent(dcp->rproc->dev.parent, size, &dma_addr,
					    DMA_TO_DEVICE, GFP_KERNEL);
	mdelay(100);
	dma_free_noncoherent(dcp->rproc->dev.parent, size, temp_buffer, dma_addr,
			     DMA_TO_DEVICE);
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
	mdelay(100);
	mbox.payload = 0x42;
	mbox.endpoint = dcp->endpoint;
	int bufno = BUF_CALLBACK;
	mbox_copy_and_send(dcp->chan, &mbox);
	static_address += size;
}

static void init_buffer(struct apple_asc_dcp *dcp)
{
	struct iommu_domain *domain = iommu_domain_alloc(dcp->display_dev->bus);
	iommu_attach_device(domain, dcp->display_dev);
	extern u64 get_fb_physical_address(void);
	iommu_map(domain, 0xa0000000, get_fb_physical_address(), 32<<20, IOMMU_READ|IOMMU_WRITE);
	*(u64 *)phys_to_virt(0x9fff78280) =
		*(u64 *)phys_to_virt(0x9fff48280);
}

static void apple_asc_dcp_work_map_buffer_func(struct work_struct *work)
{
	struct apple_asc_dcp *dcp = container_of(work, struct apple_asc_dcp, work_map_physical);
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
	struct apple_asc_dcp_remote_buffer *rbuf;
	list_for_each_entry(rbuf, &dcp->rbufs, list) {
		if (rbuf->id == m->in.bufid)
			break;
	}
	if (list_entry_is_head(rbuf, &dcp->rbufs, list)) {
		printk("not found!\n");
		return;
	}
	/* map_buffer */
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


static void apple_asc_dcp_work_allocate_buffer_func(struct work_struct *work)
{
	struct apple_asc_dcp *dcp = container_of(work, struct apple_asc_dcp, work_map_physical);
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
	struct apple_asc_dcp_remote_buffer *rbuf = kzalloc(sizeof *rbuf, GFP_KERNEL);
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
	m->out.paddr = 0;
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

#if 0
static void apple_asc_dcp_work_hardware_boot_func(struct work_struct *work)
{
	struct apple_asc_dcp *dcp = container_of(work, struct apple_asc_dcp, work_hardware_boot);
	struct apple_dcp_mbox_msg *msg = kzalloc(1024*1024, GFP_KERNEL);
	u32 data[2] = { 6, };
	u32 update_notify_clients_dcp_data[] = {
		0,0,0,0,0,0,1,1,1,0,1,1,1,
	};
	/* A407: swap_start(swapid, io_user_client) */
	struct apple_asc_dcp_io_user_client {
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
	apple_asc_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);

	msleep(1000);
	/* A443: do_create_default_frame_buffer() */
	msg->dcp.code = FOURCC("A443");
	msg->dcp.len_input = 0;
	msg->dcp.len_output = 4;
	apple_asc_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);

	msleep(1000);
	/* A029: setup_video_limits() */
	msg->dcp.code = FOURCC("A029");
	msg->dcp.len_input = 0;
	msg->dcp.len_output = 0;
	apple_asc_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);

	msleep(1000);
	/* A463: flush_supportsPower(true) */
	msg->dcp.code = FOURCC("A463");
	msg->dcp.len_input = 4;
	msg->dcp_data[0] = 1;
	msg->dcp_data[1] = 0;
	msg->dcp_data[2] = 0;
	msg->dcp_data[3] = 0;
	msg->dcp.len_output = 0;
	apple_asc_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);
	msg->dcp_data[0] = 0;
	msleep(1000);

#if 0
	/* A000: late_init_signal() */
	msg->dcp.code = FOURCC("A000");
	msg->dcp.len_input = 0;
	msg->dcp.len_output = 4;
	apple_asc_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);
#endif
	

	/* A460: setDisplayRefreshProperties() */
	msg->dcp.code = FOURCC("A460");
	msg->dcp.len_input = 0;
	msg->dcp.len_output = 4;
	apple_asc_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);

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
	apple_asc_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);

	/* A447: enable_disable_video_power_savings(0) */
	msg->dcp.code = FOURCC("A447");
	msg->dcp.len_input = 4;
	msg->dcp.len_output = 4;
	memset(msg->dcp_data, 0, 4);
	apple_asc_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);

	/* A034: update_notify_clients_dcp([...]) */
	msg->dcp.code = FOURCC("A034");
	msg->dcp.len_input = 0x34;
	msg->dcp.len_output = 0;
	memcpy(msg->dcp_data, update_notify_clients_dcp_data, sizeof(update_notify_clients_dcp_data));
	apple_asc_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);

	/* A454: first_client_open() */
	msg->dcp.code = FOURCC("A454");
	msg->dcp.len_input = 0;
	msg->dcp.len_output = 0;
	apple_asc_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);

	msg->dcp.code = FOURCC("A469");
	msg->dcp.len_input = 0;
	msg->dcp.len_output = 4;
	apple_asc_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);

	msg->dcp.code = FOURCC("A411");
	msg->dcp.len_input = 0;
	msg->dcp.len_output = 4;
	apple_asc_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);

	if (0){
		/* A468: setPowerState(1, 0, 0) */
		msg->dcp.code = FOURCC("A468");
		msg->dcp.len_input = 12;
		msg->dcp.len_output = 8;
		memcpy(msg->dcp_data, powerstate_data, 12);
		apple_asc_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);
	}

	msleep(1000);
	{
		/* A468: setPowerState(1, 0, 0) */
		msg->dcp.code = FOURCC("A468");
		msg->dcp.len_input = 12;
		msg->dcp.len_output = 8;
		memcpy(msg->dcp_data, powerstate_data, 12);
		apple_asc_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);
	}

	{
		/* A412: setDigitalMode(0x59, 0x43) */
		const u32 mode_args[] = { 0x59, 0x43 };
		msg->dcp.code = FOURCC("A412");
		msg->dcp.len_input = 8;
		msg->dcp.len_output = 4;
		memcpy(msg->dcp_data, mode_args, sizeof(mode_args));
		apple_asc_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);
	}

#if 0
	/* A000: late_init_signal() */
	msg->dcp.code = FOURCC("A000");
	msg->dcp.len_input = 0;
	msg->dcp.len_output = 4;
	apple_asc_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);
#endif

	init_buffer(dcp);
	u32 delay = 2000;
	while (1) {
		msg->dcp.code = FOURCC("A407");
		msg->dcp.len_input = sizeof(io_user_client.in);
		msg->dcp.len_output = sizeof(io_user_client.out);
		memcpy(msg->dcp_data, &io_user_client, sizeof(io_user_client));
		apple_asc_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);
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
			apple_asc_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);
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
		/* swap_submit_dcp */
		/* A408: swap_submit_dcp(swap_rec, surfaces, surfaddr, false, .0, 0) */
		msg->dcp.code = FOURCC("A408");
		msg->dcp.len_input = 0xb64; // sizeof(swapid) + sizeof(swap_submit);
		msg->dcp.len_output = 8;
		memcpy(msg->dcp_data, swap_submit, sizeof(*swap_submit));
		memset((void *)(&msg->dcp) + 0x475, 1, 1);
		memset((void *)(&msg->dcp) + 0xb6b, 1, 3);
		apple_asc_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);
		{
			/* A412: setDigitalMode(0x59, 0x43) */
			const u32 mode_args[] = { 0x59, 0x43 };
			msg->dcp.code = FOURCC("A412");
			msg->dcp.len_input = 8;
			msg->dcp.len_output = 4;
			memcpy(msg->dcp_data, mode_args, sizeof(mode_args));
			apple_asc_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);
		}
		msleep(30000);
	}
#if 0
	/* A000: late_init_signal() */
	msg->dcp.code = FOURCC("A000");
	msg->dcp.len_input = 0;
	msg->dcp.len_output = 4;
	apple_asc_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);
#endif
	if (0) {

		/* A412: setDigitalMode(0x59, 0x43) */
		const u32 mode_args[] = { 0x59, 0x43 };
		msg->dcp.code = FOURCC("A412");
		msg->dcp.len_input = 8;
		msg->dcp.len_output = 4;
		memcpy(msg->dcp_data, mode_args, sizeof(mode_args));
		apple_asc_dcp_transaction(&dcp->downstream_chans[STREAM_COMMAND], msg);
		msleep(10000);
	}

	dcp->reached_hardware_boot = 1;
	return;
}
#endif

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

static int apple_asc_dcp_send_ack(struct apple_asc_dcp *dcp, int stream)
{
	struct apple_mbox_msg mbox;
	mbox.payload = stream_to_ack(stream);
	mbox.endpoint = dcp->endpoint;
	mbox_copy_and_send(dcp->chan, &mbox);
	return 0;
}

static size_t
apple_asc_dcp_buf_alloc(struct apple_asc_dcp *dcp, int bufno, size_t size)
{
	unsigned long flags;
	size_t ret = -1;
	if (dcp->buf[bufno].off + size <= dcp->buf[bufno].size) {
		ret = dcp->buf[bufno].off;
		dcp->buf[bufno].off += size;
	} else {
		dev_warn(dcp->dev, "out of memory, this shouldn't happen!\n");
	}
	return ret;
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
	struct apple_asc_dcp_shmem_msg *shmem_msg = kzalloc(sizeof(*shmem_msg),
						       GFP_KERNEL);

	if (!shmem_msg)
		return NULL;

	shmem_msg->stream = stream;
	shmem_msg->bufno = bufno;

	shmem_msg->size_raw = msg_size;
	shmem_msg->size_roundup = round_up(msg_size, 0x40);
	shmem_msg->buf_off = apple_asc_dcp_buf_alloc(dcp, bufno,
						     shmem_msg->size_roundup);
	if (shmem_msg->buf_off == -1) {
		kfree(shmem_msg);
		return NULL;
	}
	printk("bufno %d @ %p + %016llx\n", bufno, dcp->buf[bufno].base, shmem_msg->buf_off);
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
	int bufno = stream_to_bufno(stream);
	size_t msg_size = apple_dcp_msg_size(msg_header);
	struct apple_asc_dcp_shmem_msg* shmem_msg;
	struct apple_mbox_msg mbox;
	unsigned long flags;

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
	struct apple_mbox_msg mbox;

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

	if (memcmp(msg_header, "321D", 4) &&
	    memcmp(msg_header, "565D", 4))
		apple_dcp_msg_print(msg_header);

	BUG_ON(!shmem_msg);
	apple_asc_dcp_send_ack(dcp, stream);

	list_del(&shmem_msg->list);
	kfree(shmem_msg);

	BUG_ON(apple_asc_dcp_find_shmem_msg(dcp, msg_header, stream));

	return 0;
}

static void apple_asc_dcp_receive_data(struct mbox_client *cl, void *mbox_msg)
{
	struct apple_asc_dcp *dcp = container_of(cl, struct apple_asc_dcp, cl);
	struct apple_mbox_msg *msg = mbox_msg;
	u64 payload = msg->payload;
	unsigned type = payload & 0xF;
	unsigned long flags;
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
		BUG_ON(apple_asc_dcp_find_shmem_msg(dcp, NULL, stream));
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
		BUG_ON(!apple_asc_dcp_find_shmem_msg(dcp, buf_msg, stream));
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
	BUG_ON(1);
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
	unsigned long flags;
	dma_addr_t iova;
	struct apple_mbox_msg msg;

	dcp = devm_kzalloc(&pdev->dev, sizeof(*dcp), GFP_KERNEL);
	if (!dcp)
		return -ENOMEM;

	dcp->dev = &pdev->dev;
	dcp->buf_va_size = 0x200000;
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

	INIT_LIST_HEAD(&dcp->rbufs);
	INIT_LIST_HEAD(&dcp->shmem_messages);
	for (i = 0; i < N_BUFFERS; i++)
		INIT_LIST_HEAD(&dcp->buf[i].states);
	for (i = 0; i < N_STREAMS; i++)
		dcp->downstream_chans[i].con_priv = dcp;

	dcp->mbox_controller.dev = dcp->dev;
	dcp->mbox_controller.ops = &apple_asc_dcp_mbox_chan_ops;
	dcp->mbox_controller.chans = dcp->downstream_chans;
	dcp->mbox_controller.num_chans = N_STREAMS;
	dcp->mbox_controller.txdone_irq = true;

	dma_set_mask_and_coherent(dcp->dev, DMA_BIT_MASK(32));
	dcp->buf_va = dma_alloc_coherent(dcp->dev, dcp->buf_va_size,
					 &iova, GFP_KERNEL);

	printk("va %p\n", dcp->buf_va);
	if (!dcp->buf_va)
		return -ENOMEM;

	memset(dcp->buf_va, 0, dcp->buf_va_size);
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

	msleep(1000);
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
