// SPDX-License-Identifier: GPL-2.0-only
/* Horribly mutilated by Pip Cet <pipcet@gmail.com> */
/* Copyright 2021 Alyssa Rosenzweig <alyssa@rosenzweig.io> */
/* Main driver for the DCP-based Apple SoC framebuffer.
 *
 * This device is horrible: to communicate with it enough to get a
 * basic framebuffer (and, with MacOS 12, that is required to get a
 * framebuffer at all), you need to talk to a mailbox behind another
 * mailbox behind yet another mailbox.
 *
 * apple-mailbox implements support for a basic single-channel mailbox
 * with the convenient message size of 72 bits.
 *
 * apple-asc uses 8 of these bits to identify endpoints, providing
 * 64-bit mailboxes for each of the endpoints. This is necessary
 * because all of the endpoints share a single queue, so exposing them
 * as separate mailboxes from the beginning might result in a
 * situation where too many messages are written at once, and dropped.
 *
 * apple-asc-dcp talks to one of those end points to set up a shared
 * memory buffer, and to receive and send message announcements over
 * the endpoint, while the actual messages live in the shared memory
 * buffer. It exposes that message protocol as more mailboxes: one to
 * send commands, one to receive callbacks, and two more to send
 * nested commands and receive "asynchronous" callbacks.
 *
 * (Or "a" shared memory buffer. There are actually three different
 * kinds, living behind three different IOMMU streams, for the
 * framebuffer, "PIODMA" RAM (whatever that is), and the DCP heap).
 *
 * apple-dcp talks to that high-level mailbox to exchange messages
 * with the DCP, some of which concern the creation of additional
 * memory buffers. One of them, in particular, "swaps" a memory buffer
 * so it becomes the current framebuffer. Of course, it does so
 * asynchronously, so you have to listen to another mailbox to figure
 * out whether your swap has been successful.
 *
 * So at the end of this process, we receive a mailbox message to
 * receive an endpoint message to receive a shmem message to let us
 * know our swap has been handled.
 *
 * If the slightest thing goes wrong (and remember, we don't have a
 * framebuffer yet), the whole thing crashes, the screen goes black,
 * and the only known way to recover is a reboot. There's a crash log,
 * but half of the time, it doesn't contain a readable message.
 *
 * And the sequences we've worked out are timing sensitive: when you
 * switch digital modes, it seems you have to wait for the link to
 * come up (so you need to delay), then swap in a new framebuffer
 * immediately or the link will go back down (so you can't delay too
 * much). 2.5 seconds appears to be right for my particular hardware
 * setup.
 *
 * And once you've gone through this entire dance and gotten a
 * framebuffer, you (or well, I) might want to switch kernels: we
 * don't know how to tear down things, and there's no good API for
 * forcing the page tables to live in reserved memory somewhere, so
 * we've got to protect:
 *
 *  - the frame buffer, obviously
 *  - the DCP shared memory buffer
 *  - other DCP buffers
 *  - other PIODMA buffers
 *  - the ioreport log buffer
 *  - the syslog buffer
 *  - the crash log buffer
 *  - page tables for all of the above
 *
 * You've also got to remember some DCP state.
 */
/* Based on meson driver which is
 * Copyright (C) 2016 BayLibre, SAS
 * Author: Neil Armstrong <narmstrong@baylibre.com>
 * Copyright (C) 2015 Amlogic, Inc. All rights reserved.
 * Copyright (C) 2014 Endless Mobile
 */

#include <linux/apple-asc.h>
#include <linux/backlight.h>
#include <linux/clk.h>
#include <linux/component.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/iommu.h>
#include <linux/kvbox.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of_device.h>
#include <linux/of_graph.h>
#include <linux/of_reserved_mem.h>
#include <linux/permalloc.h>
#include <linux/pm_runtime.h>

#define N_STREAMS		4
#define STREAM_COMMAND		0 /* ping pong: receive msg, send modified msg */
#define STREAM_CALLBACK		1 /* pong ping: send msg, receive modified msg */
#define STREAM_ASYNC		2 /* pong ping */
#define STREAM_NESTED_COMMAND	3 /* ping pong */

struct apple_dcp;
struct apple_dcp_stream {
	struct apple_dcp *self;
	struct mbox_client cl;
	struct mbox_chan *dcp;
	struct completion complete;
};
struct apple_dcp_rbuf {
	struct list_head list;
	u32 id;
	u64 dva;
	void *va;
	u64 size;
};

struct list_msg {
	struct list_head list;
	int stream;
	struct apple_dcp_msg *msg;
};

struct apple_dcp {
	struct device *dev;
	struct mutex mutex;
	bool forced_to_4k;
	bool powered;
	struct apple_dcp_stream stream[N_STREAMS];
	struct kvbox kvbox;
	struct work_struct work_apply;
	struct work_struct work_callback;
	struct work_struct work_modeset;
	struct apple_dcp_msg_header *msg;
	spinlock_t lock;
	bool write;
	struct kvbox_prop *prop;
	void __iomem *regs;
	dma_addr_t dummy_buffer;

	/* void *va_fb; */
	dma_addr_t dva_display;
	dma_addr_t dva_framebuffer;

	u32 rbuf_id;
	struct list_head rbufs;
	struct list_head callback_messages;
	struct list_head debugfs_messages;
	u32 *regdump;
	struct backlight_device *backlight;

	struct device *display;
	struct device *fb;
};

static void callback_return_zero(struct apple_dcp *dcp,
				 struct apple_dcp_msg *msg)
{
	memset(msg->data + msg->header.len_input, 0, msg->header.len_output);
}

static void callback_return_one(struct apple_dcp *dcp, struct apple_dcp_msg *msg)
{
	memset(msg->data + msg->header.len_input, 1, 1);
}

static void callback_clock_frequency(struct apple_dcp *dcp, struct apple_dcp_msg *msg)
{
	u32 out[] = { 533333328 };
	memcpy(msg->data, out, sizeof(out));
}

static void callback_bandwidth_setup(struct apple_dcp *dcp, struct apple_dcp_msg *msg)
{
	u32 out[] = { 0, 0, 0x3b738014, 0x2, 0x3bc3c000, 0x2, 0, 2 };
	memcpy(msg->data, out, sizeof(out));
}

static void callback_device_memory(struct apple_dcp *dcp, struct apple_dcp_msg *msg)
{
	u32 out[] = { 0x3b3d0000, 2, 0x4000, 0 };
	memcpy(msg->data, out, sizeof(out));
}

static void callback_hotplug(struct apple_dcp *dcp, struct apple_dcp_msg *msg)
{
	if (dcp->powered)
		schedule_work(&dcp->work_modeset);
}

extern u64 get_fb_physical_address(u64 *, u64 *);

static u64 apple_get_fb_dva(struct apple_dcp *dcp, u64 *width, u64 *height)
{
	struct device *dev = dcp->fb;
	static dma_addr_t dma_addr;
	u64 base = get_fb_physical_address(width, height);

	BUG_ON(!dcp->fb);

	if (!dma_addr) {
		struct iommu_domain *domain;
		size_t off;
		struct iommu_iotlb_gather gather = {};
		dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32));
		/* XXX work out why dma_alloc_coherent doesn't work here. */
		/* va = dma_alloc_noncoherent(dev, 32<<20, &dma_addr, DMA_TO_DEVICE, GFP_KERNEL); */
		domain = iommu_get_domain_for_dev(dcp->display);
		for (off = 0; off < (32<<20); off += 16384)
			iommu_map(domain, 0xa0000000+off, base+off, 16384, IOMMU_READ|IOMMU_WRITE);
		dma_addr = 0xa0000000;
		/* XXX: we need to flush the new PTEs to the old page
		 * tables, but as the TTBRs are locked, we have to do
		 * so explicitly. */
		iommu_iotlb_sync(domain, &gather); permalloc_init();
		/* ... but at least we no longer do it this way. */
		if (0)
			*(u64 *)phys_to_virt(0x9fff78280) =
				*(u64 *)phys_to_virt(0x9fff48280);
		/* dcp->va_fb = va; */
	}
	return dma_addr;
}

static void callback_map_buffer(struct apple_dcp *dcp, struct apple_dcp_msg *msg)
{
	struct apple_dcp_msg_map_buffer {
		struct apple_dcp_msg_header header;
		struct {
			u32 rbuf_id;
			u64 unk;
		} __attribute__((packed)) in;
		struct {
			u64 va;
			u64 dva;
			u32 unk;
		} __attribute__((packed)) out;
	} __attribute__((packed)) *m =
		container_of(&msg->header, struct apple_dcp_msg_map_buffer,
			     header);
	struct apple_dcp_rbuf *rbuf;
	void *va;
	struct iommu_domain *domain;

	BUG_ON(!dcp->display);

	domain = iommu_get_domain_for_dev(dcp->display);
	list_for_each_entry(rbuf, &dcp->rbufs, list) {
		if (rbuf->id == m->in.rbuf_id)
			break;
	}
	if (list_entry_is_head(rbuf, &dcp->rbufs, list)) {
		dev_err(dcp->dev, "rbuf not found!\n");
		return;
	}

	m->out.va = 0;
	m->out.unk = 0;
	rbuf->dva = dcp->dva_display;
	iommu_attach_device(domain, dcp->display);
	dma_set_mask_and_coherent(dcp->display, DMA_BIT_MASK(32));
	for (va = rbuf->va; va < rbuf->va + rbuf->size; va += 16384) {
		iommu_map(domain, rbuf->dva + (va - rbuf->va),
			  virt_to_phys(va), 16384, IOMMU_READ|IOMMU_WRITE);
	}
	m->out.dva = rbuf->dva;
	dcp->dva_display += rbuf->size;
}

static void callback_allocate_buffer(struct apple_dcp *dcp, struct apple_dcp_msg *msg)
{
	struct apple_dcp_msg_allocate_buffer {
		struct apple_dcp_msg_header header;
		struct {
			u32 unk0;
			u64 size;
			u64 unk1;
		} __attribute__((packed)) in;
		struct {
			u64 pa;
			u64 dva;
			u64 size;
			u32 mapid;
		} __attribute__((packed)) out;
	} __attribute__((packed)) *m = (void *)msg;
	dma_addr_t dma_addr;
	struct apple_dcp_rbuf *rbuf = devm_kzalloc(dcp->dev, sizeof *rbuf,
						   GFP_KERNEL);
	void *va = dma_alloc_noncoherent(dcp->dev, m->in.size,
					 &dma_addr, DMA_TO_DEVICE, GFP_KERNEL);
	if (!rbuf || !va) {
		dev_err(dcp->dev, "allocation failed!\n");
		return;
	}
	permalloc_memory(dcp->dev, va, m->in.size);
	/* we don't allocate a physically contiguous buffer,
	 * necessarily, and why would a device behind an IOMMU care
	 * about a physical address in the first place? */
	m->out.pa = 0;
	m->out.dva = dma_addr;
	m->out.size = m->in.size;
	m->out.mapid = ++dcp->rbuf_id;
	rbuf->id = m->out.mapid;
	rbuf->dva = m->out.dva;
	rbuf->va = va;
	rbuf->size = m->out.size;
	list_add(&rbuf->list, &dcp->rbufs);
}

static void callback_map_physical(struct apple_dcp *dcp, struct apple_dcp_msg *msg)
{
	struct iommu_domain *domain = iommu_get_domain_for_dev(dcp->dev);
	struct apple_dcp_msg_map_physical {
		struct apple_dcp_msg_header header;
		struct {
			u64 a;
			u64 b;
			u64 pa;
			u64 size;
		} __attribute__((packed)) in;
		struct {
			u64 dva;
			u64 size;
			u32 mapid;
		} __attribute__((packed)) out;
	} __attribute__((packed)) *m = (void *)msg;
	dma_addr_t dma_addr = 0xc0000000;
	iommu_attach_device(domain, dcp->dev);
	m->out.dva = dma_addr;
	m->out.size = m->in.size;
	m->out.mapid = ++dcp->rbuf_id;
}

static void callback_edt_data(struct apple_dcp *dcp, struct apple_dcp_msg *msg)
{
	memset(msg->data + msg->header.len_input, 2, 1);
}

struct apple_dcp_callback {
	u32 fourcc;
	void (*callback)(struct apple_dcp *dcp, struct apple_dcp_msg *msg);
};

#define callback_nop callback_return_zero

static struct apple_dcp_callback apple_dcp_callbacks[] = {
	{ FOURCC("D000"), callback_return_one },
	{ FOURCC("D001"), callback_return_one },
	{ FOURCC("D003"), callback_bandwidth_setup },
	{ FOURCC("D101"), callback_return_zero },
	{ FOURCC("D107"), callback_return_one },
	{ FOURCC("D108"), callback_return_one },
	{ FOURCC("D109"), callback_return_one },
	{ FOURCC("D110"), callback_return_one },
	{ FOURCC("D111"), callback_return_zero },
	{ FOURCC("D116"), callback_return_one },
	{ FOURCC("D118"), callback_return_zero },
	{ FOURCC("D120"), callback_edt_data },
	{ FOURCC("D122"), callback_return_one },
	{ FOURCC("D123"), callback_return_one },
	{ FOURCC("D124"), callback_return_one },
	{ FOURCC("D201"), callback_map_buffer },
	{ FOURCC("D206"), callback_return_one },
	{ FOURCC("D207"), callback_return_one },
	{ FOURCC("D211"), callback_return_zero },
	{ FOURCC("D300"), callback_nop },
	{ FOURCC("D401"), callback_return_zero },
	{ FOURCC("D408"), callback_clock_frequency },
	{ FOURCC("D411"), callback_device_memory },
	{ FOURCC("D413"), callback_return_one },
	{ FOURCC("D414"), callback_return_one },
	{ FOURCC("D415"), callback_return_one },
	{ FOURCC("D451"), callback_allocate_buffer },
	{ FOURCC("D452"), callback_map_physical },
	{ FOURCC("D552"), callback_return_one },
	{ FOURCC("D561"), callback_return_one },
	{ FOURCC("D563"), callback_return_one },
	{ FOURCC("D565"), callback_return_one },
	{ FOURCC("D567"), callback_return_one },
	{ FOURCC("D574"), callback_return_zero },
	{ FOURCC("D576"), callback_hotplug },
	{ FOURCC("D598"), callback_return_zero },
};

static struct apple_dcp *apple_dcp;

static int apple_dcp_init(struct apple_dcp *apple);
static void apple_dcp_init_maybe(struct apple_dcp *dcp)
{
	if (!dcp->fb)
		return;

	if (!dcp->display)
		return;

	apple_dcp_init(dcp);
}

void apple_dcp_set_display(struct apple_dcp *dcp, struct device *display)
{
	if (dcp == NULL)
		dcp = apple_dcp;
	if (dcp == NULL)
		return;
	dcp->display = display;
	apple_dcp_init_maybe(dcp);
}
EXPORT_SYMBOL(apple_dcp_set_display);

void apple_dcp_set_fb(struct apple_dcp *dcp, struct device *fb)
{
	if (dcp == NULL)
		dcp = apple_dcp;
	if (dcp == NULL)
		return;
	dcp->fb = fb;
	apple_dcp_init_maybe(dcp);
}
EXPORT_SYMBOL(apple_dcp_set_fb);

struct apple_dcp_msg_set_power_state {
	struct apple_dcp_msg_header header;
	u32 in[3];
	u32 out[2];
} __attribute__((packed));

static int apple_fw_call(struct apple_dcp *dcp,
			 struct apple_dcp_msg_header *header,
			 int stream)
{
	struct apple_dcp_msg *msg = container_of(header, struct apple_dcp_msg, header);
	int ret = 0;

	mutex_lock(&dcp->mutex);
	reinit_completion(&dcp->stream[stream].complete);
	mbox_send_message(dcp->stream[stream].dcp, msg);
	wait_for_completion(&dcp->stream[stream].complete);
	mutex_unlock(&dcp->mutex);

	return ret;
}

static int apple_dcp_init_4k(struct apple_dcp *);

#define INIT_APPLE_DCP_MSG(ptr, code_str)  do {			\
		(ptr)->header.code = FOURCC(code_str);		\
		(ptr)->header.len_input = sizeof((ptr)->in);	\
		(ptr)->header.len_output = sizeof((ptr)->out);	\
	} while (0)

void apple_dcp_set_power(struct apple_dcp *dcp, int state)
{
	struct apple_dcp_msg_set_power_state a468 = {
		.in = { },
	};
	if (dcp == NULL)
		dcp = apple_dcp;
	if (dcp == NULL)
		return;
	INIT_APPLE_DCP_MSG(&a468, "A468");
	a468.in[0] = !!state;
	dcp->powered = a468.in[0];
	apple_fw_call(dcp, &a468.header, STREAM_COMMAND);
	if (state != 0) {
		schedule_work(&dcp->work_modeset);
	}
}
EXPORT_SYMBOL(apple_dcp_set_power);

static void apple_dcp_single_callback(struct apple_dcp *dcp, struct apple_dcp_msg *msg)
{
	struct apple_dcp_callback *callback = apple_dcp_callbacks;

	while (callback < apple_dcp_callbacks + sizeof(apple_dcp_callbacks)/sizeof(apple_dcp_callbacks[0])) {
		if (callback->fourcc == msg->header.code) {
			dev_info(dcp->dev, "callback %c%c%c%c found!\n",
				 FOURCC_CHARS(msg->header.code));
			callback_return_zero(dcp, msg);
			callback->callback(dcp, msg);
			return;
		}
		callback++;
	}

	dev_err(dcp->dev, "callback %c%c%c%c not found!\n",
		FOURCC_CHARS(msg->header.code));
	callback_return_zero(dcp, msg);
}

static void apple_dcp_work_callback_func(struct work_struct *work)
{
	struct apple_dcp *dcp = container_of(work, struct apple_dcp, work_callback);

	while (!list_empty(&dcp->callback_messages)) {
		struct list_msg *list_msg =
			list_first_entry(&dcp->callback_messages,
					 struct list_msg, list);
		struct apple_dcp_msg *msg = list_msg->msg;
		int stream = list_msg->stream;
		list_del(&list_msg->list);
		apple_dcp_single_callback(dcp, msg);
		mbox_send_message(dcp->stream[stream].dcp, msg);
		devm_kfree(dcp->dev, list_msg);
	}
}

static void apple_dcp_work_apply_func(struct work_struct *work)
{
	struct apple_dcp *dcp = container_of(work, struct apple_dcp, work_apply);
	unsigned long flags;

	spin_lock_irqsave(&dcp->lock, flags);
	if (dcp->write) {
		struct apple_dcp_msg_header *msg = dcp->msg;
		int ret;
		spin_unlock_irqrestore(&dcp->lock, flags);

		ret = apple_fw_call(dcp, msg, STREAM_COMMAND);

		kfree(msg);
		spin_lock_irqsave(&dcp->lock, flags);
		dcp->write = false;
		dcp->prop = NULL;
	}
	spin_unlock_irqrestore(&dcp->lock, flags);
}

struct apple_dcp_msg_apply_property {
	struct apple_dcp_msg_header header;
	struct {
		u32 key;
		u32 val;
	} __attribute__((packed)) in;
	struct {
		u32 ret;
	} __attribute__((packed)) out;
};

static int apple_dcp_kvbox_write(struct kvbox *kvbox, struct kvbox_prop *prop)
{
	struct apple_dcp *dcp = kvbox->priv;
	size_t key_len = prop->key_len;
	size_t val_len = prop->data_len;
	struct apple_dcp_msg_apply_property *msg =
		kzalloc(sizeof(*msg) + 0x100, GFP_KERNEL);
	u32 key;
	u32 val;
	int ret;
	unsigned long flags;

	if (!msg)
		return -ENOMEM;

	if (key_len != 8)
		return -EINVAL;

	if (val_len != 4)
		return -EINVAL;

	ret = kstrtou32(prop->key, 16, &key);
	if (ret < 0)
		return ret;

	memcpy(&val, prop->data, sizeof(val));

	if (!spin_trylock_irqsave(&dcp->lock, flags))
		return -EBUSY;

	if (dcp->prop) {
		spin_unlock_irqrestore(&dcp->lock, flags);
		return -EBUSY;
	}

	dcp->prop = prop;
	dcp->write = true;

	INIT_APPLE_DCP_MSG(msg, "A352");
	msg->in.key = key;
	msg->in.val = val;

	dcp->msg = &msg->header;
	schedule_work(&dcp->work_apply);

	spin_unlock_irqrestore(&dcp->lock, flags);
	if (ret < 0)
		return ret;

	kvbox_done(&dcp->kvbox);

	return 0;
}

static const struct kvbox_ops apple_dcp_kvbox_ops = {
	.write = apple_dcp_kvbox_write,
};

static int apple_dcp_command_debugfs_show(struct seq_file *s, void *ptr)
{
	struct apple_dcp *dcp = s->private;
	struct list_msg *list_msg;

	if (list_empty(&dcp->debugfs_messages))
		return 0;

	list_msg = list_first_entry(&dcp->debugfs_messages, struct list_msg, list);
	seq_write(s, list_msg->msg, apple_dcp_msg_size(&list_msg->msg->header));
	list_del(&list_msg->list);
	devm_kfree(dcp->dev, list_msg->msg);
	devm_kfree(dcp->dev, list_msg);

	return 0;
}

static ssize_t apple_dcp_command_debugfs_write(struct file *file,
					       const char __user *user_buf,
					       size_t size, loff_t *ppos)
{
	struct seq_file *s = file->private_data;
	struct apple_dcp *dcp = s->private;
	struct apple_dcp_msg *msg = devm_kzalloc(dcp->dev, size, GFP_KERNEL);
	struct list_msg *list_msg;
	int ret;

	if (size < 12) {
		devm_kfree(dcp->dev, msg);
		return -EINVAL;
	}

	if (copy_from_user(msg, user_buf, size)) {
		devm_kfree(dcp->dev, msg);
		return -EFAULT;
	}

	if (apple_dcp_msg_size(&msg->header) != size) {
		void *msg2 = devm_kzalloc(dcp->dev, apple_dcp_msg_size(&msg->header), GFP_KERNEL);
		memcpy(msg2, msg, size);
		devm_kfree(dcp->dev, msg);
		msg = msg2;
	}
	*ppos += size;

	list_msg = devm_kzalloc(dcp->dev, sizeof *list_msg, GFP_KERNEL);
	if (!list_msg) {
		devm_kfree(dcp->dev, msg);
		return -ENOMEM;
	}

	ret = apple_fw_call(dcp, &msg->header, STREAM_COMMAND);
	if (ret) {
		devm_kfree(dcp->dev, list_msg);
		devm_kfree(dcp->dev, msg);
		return ret;
	}

	list_msg->msg = msg;
	list_add(&list_msg->list, &dcp->debugfs_messages);

	return size;
}

DEFINE_SHOW_ATTRIBUTE(apple_dcp_command_debugfs);
static const struct file_operations real_apple_dcp_command_debugfs_fops = {
	.owner = THIS_MODULE,
	.open = apple_dcp_command_debugfs_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = apple_dcp_command_debugfs_write,
};

static void apple_dcp_debugfs_init_command(struct apple_dcp *dcp, struct dentry *dentry)
{
	debugfs_create_file("command", 0600, dentry, dcp,
			    &real_apple_dcp_command_debugfs_fops);
}


static int apple_dcp_trigger_debugfs_show(struct seq_file *s, void *ptr)
{
	return 0;
}

static ssize_t apple_dcp_trigger_debugfs_write(struct file *file,
					       const char __user *user_buf,
					       size_t size, loff_t *ppos)
{
	struct seq_file *s = file->private_data;
	struct apple_dcp *dcp = s->private;

	schedule_work(&dcp->work_modeset);
	*ppos += size;

	return size;
}

DEFINE_SHOW_ATTRIBUTE(apple_dcp_trigger_debugfs);
static const struct file_operations real_apple_dcp_trigger_debugfs_fops = {
	.owner = THIS_MODULE,
	.open = apple_dcp_trigger_debugfs_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = apple_dcp_trigger_debugfs_write,
};

static void apple_dcp_debugfs_init_trigger(struct apple_dcp *dcp, struct dentry *dentry)
{
	debugfs_create_file("trigger", 0600, dentry, dcp,
			    &real_apple_dcp_trigger_debugfs_fops);
}

static int apple_dcp_debugfs_init(struct apple_dcp *dcp)
{
	struct dentry *dentry;

	dentry = debugfs_create_dir(dev_name(dcp->dev), NULL);

	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	apple_dcp_debugfs_init_command(dcp, dentry);
	apple_dcp_debugfs_init_trigger(dcp, dentry);

	return 0;
}

extern int apple_dcp_reached_hardware_boot(struct mbox_chan *chan,
					   struct device *dev);

static void apple_dcp_receive_data(struct mbox_client *cl, void *msg)
{
	struct apple_dcp_stream *stream =
		container_of(cl, struct apple_dcp_stream, cl);
	struct apple_dcp *dcp = stream->self;
	int streamno = stream - dcp->stream;

	switch (streamno) {
	case STREAM_COMMAND:
	case STREAM_NESTED_COMMAND:
		complete_all(&stream->complete);
		break;

	case STREAM_ASYNC:
	case STREAM_CALLBACK: {
		struct list_msg *list_msg = devm_kzalloc(dcp->dev, sizeof(*list_msg), GFP_KERNEL);
		list_msg->msg = msg;
		list_msg->stream = streamno;
		list_add(&list_msg->list, &dcp->callback_messages);
		schedule_work(&dcp->work_callback);
		break;
	}
	}
}

struct apple_dcp_msg_init {
	struct apple_dcp_msg_header header;
	struct {} __attribute__((packed)) in;
	u32 out;
} __attribute__((packed));

struct apple_dcp_msg_void {
	struct apple_dcp_msg_header header;
	struct {} __attribute__((packed)) in;
	struct {} __attribute__((packed)) out;
} __attribute__((packed));

struct apple_dcp_msg_void_int {
	struct apple_dcp_msg_header header;
	struct {} __attribute__((packed)) in;
	u32 out;
} __attribute__((packed));

struct apple_dcp_msg_int_void {
	struct apple_dcp_msg_header header;
	u32 in;
	struct {} __attribute__((packed)) out;
} __attribute__((packed));

struct apple_dcp_msg_color_remap_mode {
	struct apple_dcp_msg_header header;
	u32 in[3];
	u32 out[2];
} __attribute__((packed));

struct apple_dcp_msg_update_notify_clients {
	struct apple_dcp_msg_header header;
	u32 in[13];
	u32 out[2];
} __attribute__((packed));

struct apple_dcp_msg_begin_swap {
	struct apple_dcp_msg_header header;
	struct {
		u32 unk0;
		u64 addr; /* an unhashed kernel VA, apparently */
		u64 flags;
		u32 unk1;
	} __attribute__((packed)) in;
	struct {
		u32 swap_id;
		u32 unk0;
		u64 unk1[2];
	} __attribute__((packed)) out;
} __attribute__((packed));

struct apple_dcp_msg_swap_rect {
	u32 x, y, width, height;
} __attribute__((packed));

struct apple_dcp_msg_plane_info {
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

struct apple_dcp_msg_swaprec {
	u32 unk_mbz0[16];
	u32 flags[4];
	u32 swap_id;
	u32 surf_ids[4];
	struct apple_dcp_msg_swap_rect src_rect[4];
	u32 surf_flags[4];
	u32 surf_unk[4];
	struct apple_dcp_msg_swap_rect dst_rect[4];
	u32 swap_enabled;
	u32 swap_completed;
	u32 unk_mbz1[(0x1b8 + 0x14 + 0x3c + 12)/4];
} __attribute__((packed));

#define MAX_PLANES 3

struct apple_dcp_msg_swapsurf {
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
	struct apple_dcp_msg_plane_info planes[MAX_PLANES];
	u64 has_planes;
	u8 compression_info[MAX_PLANES * 0x34];
	u64 has_compression_info;
	u32 unk3[2];
	u8 unk4[7];
} __attribute__((packed));

struct apple_dcp_msg_start_swap {
	struct apple_dcp_msg_header header;
	struct {
		struct apple_dcp_msg_swaprec swaprec;
		struct apple_dcp_msg_swapsurf surface[4];
		u64 surf_addr[4];
		u8 unk_bool;
		u64 unk_float;
		u32 unk_int;
		u32 unk_flags;
	} __attribute__((packed)) in;
	struct {
		u64 unk;
	} __attribute__((packed)) out;
} __attribute__((packed));

struct apple_dcp_msg_set_digital_mode {
	struct apple_dcp_msg_header header;
	u32 in[3];
	u32 out[1];
} __attribute__((packed));

static int apple_dcp_init_4k(struct apple_dcp *dcp)
{
	struct apple_dcp_msg_set_digital_mode a412 = {
		.in = { 0x59, 0x43, },
	};
	struct apple_dcp_msg_begin_swap *a407 = kzalloc(sizeof *a407, GFP_KERNEL);
	struct apple_dcp_msg_start_swap *a408 = kzalloc(sizeof *a408, GFP_KERNEL);
	int delay = 2000;
	static u32 surface_id = 3; /* this works... */
	surface_id++;

	INIT_APPLE_DCP_MSG(&a412, "A412");

	INIT_APPLE_DCP_MSG(a407, "A407");
	INIT_APPLE_DCP_MSG(a408, "A408");
	a407->in.addr = 0xfffffe1667ba4a00;
	a407->in.flags = 0x0000010000000000;
	while (delay <= 3000) {
		u32 swap_id;
		u64 width, height;
		apple_fw_call(dcp, &a407->header, STREAM_COMMAND);
		swap_id = a407->out.swap_id;
		msleep(delay);
		a408->in.surf_addr[0] = apple_get_fb_dva(dcp,
							 &width,
							 &height);
		a408->in.swaprec.flags[0] = 0x861202;
		a408->in.swaprec.flags[2] = 0x04;
		a408->in.swaprec.swap_id = swap_id;
		a408->in.swaprec.surf_ids[0] = surface_id;
		a408->in.swaprec.src_rect[0].width = width;
		a408->in.swaprec.src_rect[0].height = height;
		a408->in.swaprec.surf_flags[0] = 1;
		a408->in.swaprec.dst_rect[0].width = 3840;
		a408->in.swaprec.dst_rect[0].height = 2160;
		a408->in.swaprec.swap_enabled = 0x80000007;
		a408->in.swaprec.swap_completed = 0x80000007;
		a408->in.surface[0].format = 0x42475241;
		a408->in.surface[0].unk2[0] = 0x0d;
		a408->in.surface[0].unk2[1] = 0x01;
		a408->in.surface[0].stride = width * 4;
		a408->in.surface[0].pix_size = 4;
		a408->in.surface[0].pel_w = 1;
		a408->in.surface[0].pel_h = 1;
		a408->in.surface[0].width = width;
		a408->in.surface[0].height = height;
		a408->in.surface[0].buf_size = width * height * 4;
		a408->in.surface[0].surface_id = surface_id;
		a408->in.surface[0].has_comp = 1;
		a408->in.surface[0].has_planes = 1;
		a408->header.len_input = 0xb64;
		memset((void *)a408 + 0xb6b, 1, 3);
		apple_fw_call(dcp, &a412.header, STREAM_COMMAND);
		msleep(delay);
		apple_fw_call(dcp, &a408->header, STREAM_COMMAND);
		delay += 250;
	}

	return 0;
}

static void apple_dcp_work_modeset_func(struct work_struct *work)
{
	struct apple_dcp *dcp = container_of(work, struct apple_dcp,
					     work_modeset);
	apple_dcp_init_4k(dcp);
}


static int apple_dcp_init(struct apple_dcp *dcp)
{
	struct apple_dcp_msg_init a401 = {};
	struct apple_dcp_msg_void a357 = {};
	struct apple_dcp_msg_void_int a000 = {};
	struct apple_dcp_msg_void_int a443 = {};
	struct apple_dcp_msg_void a029 = {};
	struct apple_dcp_msg_int_void a463 = {
		.in = 1,
	};
	struct apple_dcp_msg_void_int a460 = {};
	struct apple_dcp_msg_color_remap_mode a426 = {
		.in = { 6, },
	};
	struct apple_dcp_msg_color_remap_mode a447 = {};
	struct apple_dcp_msg_update_notify_clients a034 = {
		.in = { 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, }
	};
	struct apple_dcp_msg_void a454 = {};
	struct apple_dcp_msg_void_int a469 = {};
	struct apple_dcp_msg_void_int a411 = {};
	struct apple_dcp_msg_set_power_state a468 = {
		.in = { 1, },
	};
	u64 fb_width, fb_height;

	INIT_APPLE_DCP_MSG(&a000, "A000");
	INIT_APPLE_DCP_MSG(&a029, "A029");
	INIT_APPLE_DCP_MSG(&a034, "A034");
	INIT_APPLE_DCP_MSG(&a357, "A357");
	INIT_APPLE_DCP_MSG(&a401, "A401");
	INIT_APPLE_DCP_MSG(&a411, "A411");
	INIT_APPLE_DCP_MSG(&a426, "A426");
	INIT_APPLE_DCP_MSG(&a443, "A443");
	INIT_APPLE_DCP_MSG(&a447, "A447");
	INIT_APPLE_DCP_MSG(&a454, "A454");
	INIT_APPLE_DCP_MSG(&a460, "A460");
	INIT_APPLE_DCP_MSG(&a463, "A463");
	INIT_APPLE_DCP_MSG(&a468, "A468");
	INIT_APPLE_DCP_MSG(&a469, "A469");

	apple_fw_call(dcp, &a401.header, STREAM_COMMAND);
	apple_fw_call(dcp, &a357.header, STREAM_COMMAND);
	apple_fw_call(dcp, &a443.header, STREAM_COMMAND);
	apple_fw_call(dcp, &a029.header, STREAM_COMMAND);
	apple_fw_call(dcp, &a463.header, STREAM_COMMAND);
	apple_fw_call(dcp, &a460.header, STREAM_COMMAND);
	apple_fw_call(dcp, &a426.header, STREAM_COMMAND);
	apple_fw_call(dcp, &a447.header, STREAM_COMMAND);
	apple_fw_call(dcp, &a034.header, STREAM_COMMAND);
	apple_fw_call(dcp, &a454.header, STREAM_COMMAND);
	apple_fw_call(dcp, &a469.header, STREAM_COMMAND);
	apple_fw_call(dcp, &a411.header, STREAM_COMMAND);
	apple_fw_call(dcp, &a468.header, STREAM_COMMAND);
	dcp->powered = true;

	get_fb_physical_address(&fb_width, &fb_height);

	if (fb_width == 3840 && fb_height == 2160)
		apple_dcp_init_4k(dcp);

	if (fb_width == 1920 && fb_height == 1080)
		apple_dcp_init_4k(dcp);

	return 0;
}

static int apple_dcp_probe(struct platform_device *pdev)
{
	struct apple_dcp *dcp;
	int ret = 0, i;

	dcp = devm_kzalloc(&pdev->dev, sizeof *dcp, GFP_KERNEL);
	if (IS_ERR(dcp) || !dcp)
		return dcp ? PTR_ERR(dcp) : -ENOMEM;

	dcp->dev = &pdev->dev;

	dcp->dva_display = 0xb0000000;
	dcp->dva_framebuffer = 0xa0000000;
	ret = dma_set_mask_and_coherent(dcp->dev, DMA_BIT_MASK(32));
	if (ret)
		return ret;

	for (i = 0; i < N_STREAMS; i++) {
		dcp->stream[i].self = dcp;
		dcp->stream[i].cl.dev = &pdev->dev;
		dcp->stream[i].cl.rx_callback = apple_dcp_receive_data;
		dcp->stream[i].dcp = mbox_request_channel(&dcp->stream[i].cl, i);
		if (IS_ERR(dcp->stream[i].dcp)) {
			ret = PTR_ERR(dcp->stream[i].dcp);
			goto err_unload;
		}
		init_completion(&dcp->stream[i].complete);
	}

	INIT_LIST_HEAD(&dcp->rbufs);
	INIT_LIST_HEAD(&dcp->callback_messages);
	INIT_LIST_HEAD(&dcp->debugfs_messages);
	INIT_WORK(&dcp->work_callback, apple_dcp_work_callback_func);
	INIT_WORK(&dcp->work_apply, apple_dcp_work_apply_func);
	INIT_WORK(&dcp->work_modeset, apple_dcp_work_modeset_func);
	mutex_init(&dcp->mutex);
	spin_lock_init(&dcp->lock);

	apple_dcp = dcp;
	of_platform_populate(pdev->dev.of_node, NULL, NULL, &pdev->dev);

	dcp->kvbox.dev = dcp->dev;
	dcp->kvbox.ops = &apple_dcp_kvbox_ops;
	dcp->kvbox.priv = dcp;
	INIT_LIST_HEAD(&dcp->kvbox.requests);
	kvbox_register(&dcp->kvbox);

	apple_dcp_debugfs_init(dcp);

err_unload:
	return ret;
}

static int apple_dcp_remove(struct platform_device *pdev)
{
	return -EBUSY;
}

static const struct of_device_id of_match[] = {
	{ .compatible = "apple,t8103-dcp" },
	{}
};
MODULE_DEVICE_TABLE(of, of_match);

static struct platform_driver apple_platform_driver = {
	.probe	= apple_dcp_probe,
	.remove	= apple_dcp_remove,
	.driver	= {
		.name = "apple-dcp",
		.of_match_table	= of_match,
	},
};

module_platform_driver(apple_platform_driver);

MODULE_DESCRIPTION("Apple DCP (Display Control Processor?) driver");
MODULE_LICENSE("GPL v2");
