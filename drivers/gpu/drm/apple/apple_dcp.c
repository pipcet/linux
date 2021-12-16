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
 * the endpoint, while the actual mesasges live in the shared memory
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
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of_device.h>
#include <linux/of_graph.h>
#include <linux/of_reserved_mem.h>
#include <linux/pm_runtime.h>

#include <drm/drm_aperture.h>
#include <drm/drm_atomic.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_crtc.h>
#include <drm/drm_drv.h>
#include <drm/drm_fb_helper.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_fb_cma_helper.h>
#include <drm/drm_gem_cma_helper.h>
#include <drm/drm_gem_framebuffer_helper.h>
#include <drm/drm_modeset_helper.h>
#include <drm/drm_of.h>
#include <drm/drm_probe_helper.h>

#define DISP0_SURF0 0x10000
#define SURF_FORMAT 0x30
#define    SURF_FORMAT_R10G10B10X2 0x5220
#define    SURF_FORMAT_BGRA 0x5000
#define SURF_FRAMEBUFFER_0 0x54 /* start of framebuffer */
#define SURF_FRAMEBUFFER_1 0x58 /* end of framebuffer ? */

#define N_STREAMS		4
#define STREAM_COMMAND		0 /* ping pong: receive msg, send modified msg */
#define STREAM_CALLBACK		1 /* pong ping: send msg, receive modified msg */
#define STREAM_ASYNC		2 /* pong ping */
#define STREAM_NESTED_COMMAND	3 /* ping pong */

struct apple_dcp;
struct apple_drm_stream {
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
	struct apple_dcp_msg *msg;
};

struct apple_dcp {
	struct drm_device	drm;
	struct mutex		mutex;
	bool			forced_to_4k;
	struct apple_drm_stream stream[N_STREAMS];
	struct kvbox		kvbox;
	struct work_struct	work;
	struct work_struct	work_callback;
	struct apple_dcp_mbox_msg *msg;
	spinlock_t		lock;
	bool			write;
	struct kvbox_prop *	prop;
	void __iomem		*regs;
	dma_addr_t		dummy_buffer;

	u32			rbuf_id;
	struct list_head        rbufs;
	struct list_head        callback_messages;
	u32 *			regdump;
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
	callback_return_zero(dcp, msg);
	memset(msg->data + msg->header.len_input, 1, 1);
}

static void callback_clock_frequency(struct apple_dcp *dcp, struct apple_dcp_msg *msg)
{
	u32 out[] = { 533333328 };
	callback_return_zero(dcp, msg);
	memcpy(msg->data, &out, sizeof(out));
}

static void callback_bandwidth_setup(struct apple_dcp *dcp, struct apple_dcp_msg *msg)
{
	u32 out[] = { 0, 0, 0x3b738014, 0x2, 0x3bc3c000, 0x2, 0, 2 };
	callback_return_zero(dcp, msg);
	memcpy(msg->data, &out, sizeof(out));
}

static void callback_device_memory(struct apple_dcp *dcp, struct apple_dcp_msg *msg)
{
	u32 out[] = { 0x3b3d0000, 2, 0x4000, 0 };
	callback_return_zero(dcp, msg);
	memcpy(msg->data, &out, sizeof(out));
}

static void callback_map_buffer(struct apple_dcp *dcp, struct apple_dcp_msg *msg)
{
}

static void callback_allocate_buffer(struct apple_dcp *dcp, struct apple_dcp_msg *msg)
{
	struct apple_dcp_msg_map_physical {
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
	struct apple_dcp_rbuf *rbuf = devm_kzalloc(dcp->drm.dev, sizeof *rbuf,
						   GFP_KERNEL);
	void *va = dma_alloc_coherent(dcp->drm.dev, m->in.size,
				      &dma_addr, GFP_KERNEL);
	if (!rbuf || !va) {
		dev_err(dcp->drm.dev, "allocation failed!\n");
		return;
	}
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
	struct iommu_domain *domain = iommu_domain_alloc(dcp->drm.dev->bus);
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
	iommu_map(domain, dma_addr, m->in.pa, m->in.size, IOMMU_READ|IOMMU_WRITE);
	m->out.dva = dma_addr;
	m->out.size = m->in.size;
	m->out.mapid = ++dcp->rbuf_id;
}

static void callback_edt_data(struct apple_dcp *dcp, struct apple_dcp_msg *msg)
{
	callback_return_zero(dcp, msg);
	memset(msg->data + msg->header.len_input, 2, 1);
}

struct apple_dcp_callback {
	u32 fourcc;
	void (*callback)(struct apple_dcp *dcp, struct apple_dcp_msg *msg);
};

static struct apple_dcp_callback apple_dcp_callbacks[] = {
	{ FOURCC("D000"), callback_return_one },
	{ FOURCC("D001"), callback_return_one },
	{ FOURCC("D107"), callback_return_one },
	{ FOURCC("D108"), callback_return_one },
	{ FOURCC("D109"), callback_return_one },
	{ FOURCC("D110"), callback_return_one },
	{ FOURCC("D122"), callback_return_one },
	{ FOURCC("D123"), callback_return_one },
	{ FOURCC("D124"), callback_return_one },
	{ FOURCC("D206"), callback_return_one },
	{ FOURCC("D207"), callback_return_one },
	{ FOURCC("D413"), callback_return_one },
	{ FOURCC("D414"), callback_return_one },
	{ FOURCC("D415"), callback_return_one },
	{ FOURCC("D552"), callback_return_one },
	{ FOURCC("D561"), callback_return_one },
	{ FOURCC("D563"), callback_return_one },
	{ FOURCC("D565"), callback_return_one },
	{ FOURCC("D567"), callback_return_one },
	{ FOURCC("D101"), callback_return_zero },
	{ FOURCC("D111"), callback_return_zero },
	{ FOURCC("D118"), callback_return_zero },
	{ FOURCC("D574"), callback_return_zero },
	{ FOURCC("D401"), callback_return_zero },
	{ FOURCC("D120"), callback_edt_data },
	{ FOURCC("D411"), callback_device_memory },
	{ FOURCC("D201"), callback_map_buffer },
	{ FOURCC("D451"), callback_allocate_buffer },
	{ FOURCC("D452"), callback_map_physical },
	{ FOURCC("D003"), callback_bandwidth_setup },
	{ FOURCC("D116"), callback_return_one },
	{ FOURCC("D408"), callback_clock_frequency },
};

static struct apple_dcp *apple_dcp;

static int apple_dcp_init(struct apple_dcp *apple);
static void apple_dcp_init_maybe(struct apple_dcp *dcp)
{
	if (!dcp->fb)
		return;

	if (!dcp->display)
		return;

	printk("initing!\n");

	msleep(1000);
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

static int apple_match_backlight(struct device *dev, void *ptr)
{
	struct apple_dcp *apple = ptr;
	struct backlight_device *backlight;

	backlight = devm_of_find_backlight(dev);
	if (!IS_ERR(backlight))
		apple->backlight = backlight;

	return 0;
}

static void apple_find_backlight(struct apple_dcp *apple)
{
	if (!apple->backlight) {
		apple->backlight = of_find_backlight_by_node(apple->drm.dev->of_node);
		if (IS_ERR(apple->backlight))
			apple->backlight = NULL;
	}

	if (!apple->backlight) {
		apple->backlight = devm_of_find_backlight(apple->drm.dev);
		if (IS_ERR(apple->backlight))
			apple->backlight = NULL;
	}

	if (!apple->backlight) {
		device_for_each_child(apple->drm.dev, apple, apple_match_backlight);
	}
}

#define DCP_LATE_INIT_SIGNAL 0x41343031
#define DCP_SET_DIGITAL_MODE 0x41343132
#define DCP_APPLY_PROPERTY 0x41333532 /* A352: applyProperty(unsigned int, unsigned int) */

#define REGDUMP_START 0x10000
#define REGDUMP_END   0x34000

static int apple_regdump_create(struct apple_dcp *apple)
{
	int i;

	if (apple->regdump)
		return -EBUSY;

	apple->regdump = devm_kzalloc(apple->drm.dev, 0x40000, GFP_KERNEL);
	if (!apple->regdump)
		return -ENOMEM;

	for (i = REGDUMP_START / 4; i < REGDUMP_END / 4; i++)
		apple->regdump[i] = readl(apple->regs + 4 * i);

	return 0;
}

static int apple_regdump_replay(struct apple_dcp *apple)
{
	static struct {
		u32 start;
		u32 end;
		const char *description;
	} regdump_stretches[] = {
		{ 0x12000, 0x34000, "color curves" },
		{ 0x10030, 0x12000, "general FB regs" },
		{ 0x10004, 0x10014, "FB regs master off switch" },
		{ 0x10014, 0x10030, "guarded FB regs" },
		{ 0x10030, 0x10034, "pixel format" },
	};
	int i;
	u32 idx;

	if (!apple->regdump)
		return -EINVAL;

	writel(0, apple->regs + DISP0_SURF0 + 0x30);
	writel(0, apple->regs + DISP0_SURF0 + 0x04);
	for (i = 0; i < sizeof(regdump_stretches) / sizeof(regdump_stretches[0]); i++)
		for (idx = regdump_stretches[i].start; idx < regdump_stretches[i].end; idx += 4)
			writel(apple->regdump[idx/4],
			       apple->regs + idx);

	devm_kfree(apple->drm.dev, apple->regdump);

	return 0;
}

static int apple_fw_call(struct apple_dcp *apple,
			 struct apple_dcp_msg_header *header,
			 int stream)
{
	struct apple_dcp_msg *msg = container_of(header, struct apple_dcp_msg, header);
	int ret = 0;

	printk("%d\n", __LINE__); mdelay(1000);
	mutex_lock(&apple->mutex);
	printk("%d\n", __LINE__); mdelay(1000);
	reinit_completion(&apple->stream[stream].complete);
	printk("%d %p %d\n", __LINE__, apple->stream[stream].dcp, stream); mdelay(1000);
	mbox_send_message(apple->stream[stream].dcp, msg);
	printk("%d\n", __LINE__); mdelay(1000);
	wait_for_completion(&apple->stream[stream].complete);
	printk("%d\n", __LINE__); mdelay(1000);
	mutex_unlock(&apple->mutex);
	printk("%d\n", __LINE__); mdelay(1000);

	return ret;
}

static void apple_dcp_single_callback(struct apple_dcp *dcp, struct apple_dcp_msg *msg)
{
	struct apple_dcp_callback *callback = apple_dcp_callbacks;

	while (callback < apple_dcp_callbacks + sizeof(apple_dcp_callbacks)/sizeof(apple_dcp_callbacks[0])) {
		if (callback->fourcc == msg->header.code) {
			callback->callback(dcp, msg);
			return;
		}
	}

	dev_err(dcp->drm.dev, "callback not found!\n");
}

static void apple_dcp_work_func(struct work_struct *work)
{
	struct apple_dcp *dcp = container_of(work, struct apple_dcp, work_callback);

	while (!list_empty(&dcp->callback_messages)) {
		struct list_msg *list_msg =
			list_first_entry(&dcp->callback_messages,
					 struct list_msg, list);
		struct apple_dcp_msg *msg = list_msg->msg;
		apple_dcp_single_callback(dcp, msg);
		list_del(&list_msg->list);
	}
}

static void apple_write_work_func(struct work_struct *work)
{
}

static int apple_drm_write(struct kvbox *kvbox, struct kvbox_prop *prop)
{
	struct apple_dcp *apple = kvbox->priv;
	size_t key_len = prop->key_len;
	size_t val_len = prop->data_len;
	struct apple_dcp_mbox_msg *msg = kzalloc(sizeof(*msg) + 0x100,
						 GFP_KERNEL);
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

	if (!spin_trylock_irqsave(&apple->lock, flags))
		return -EBUSY;

	if (apple->prop) {
		spin_unlock_irqrestore(&apple->lock, flags);
		return -EBUSY;
	}

	apple->prop = prop;
	apple->write = true;

	msg->mbox.payload = 0x202; /* message type 2, command context */
	msg->dcp.code = DCP_APPLY_PROPERTY;
	msg->dcp.len_input = 8;
	msg->dcp.len_output = 4;
	memcpy(msg->dcp_data, &key, sizeof(key));
	memcpy(msg->dcp_data + sizeof(key), &val, sizeof(val));

	apple->msg = msg;
	schedule_work(&apple->work);

	spin_unlock_irqrestore(&apple->lock, flags);
	if (ret < 0)
		return ret;

	return 0;
}

static const struct kvbox_ops apple_drm_kvbox_ops = {
	.write = apple_drm_write,
};

#define to_apple_dcp(x) \
	container_of(x, struct apple_dcp, drm)

DEFINE_DRM_GEM_CMA_FOPS(apple_fops);

static const struct drm_driver apple_drm_driver = {
	.driver_features = DRIVER_MODESET | DRIVER_GEM | DRIVER_ATOMIC,
	.name = "apple",
	.desc = "Apple Display Controller DRM driver",
	.date = "20210801",
	.major = 1,
	.minor = 0,
	.patchlevel = 0,
	.fops = &apple_fops,
	DRM_GEM_CMA_DRIVER_OPS,
};

static int apple_plane_atomic_check(struct drm_plane *plane,
				    struct drm_atomic_state *state)
{
	/* TODO */
	return 0;

}

static void apple_plane_atomic_disable(struct drm_plane *plane,
				       struct drm_atomic_state *state)
{
	struct apple_dcp *apple = to_apple_dcp(plane->dev);
	dma_addr_t dva = apple->dummy_buffer;
	dev_info(apple->drm.dev, "disable: mapping dummy buffer\n");

	writel(dva, apple->regs + DISP0_SURF0 + SURF_FRAMEBUFFER_0);
	writel(dva + 3840 * 2160 * 4, apple->regs + DISP0_SURF0 + SURF_FRAMEBUFFER_1);
	writel(SURF_FORMAT_BGRA, apple->regs + DISP0_SURF0 + SURF_FORMAT);
}

static void apple_plane_atomic_update(struct drm_plane *plane,
				      struct drm_atomic_state *state)
{
	struct apple_dcp *apple = to_apple_dcp(plane->dev);
	struct drm_plane_state *plane_state;
	struct drm_framebuffer *fb;
	dma_addr_t dva;

	plane_state = drm_atomic_get_new_plane_state(state, plane);
	fb = plane_state->fb;
	dva = drm_fb_cma_get_gem_addr(fb, plane_state, 0);
	if (dva == 0) {
		dev_info(apple->drm.dev, "update: mapping dummy buffer\n");
		dva = apple->dummy_buffer;
	}

	writel(dva, apple->regs + DISP0_SURF0 + SURF_FRAMEBUFFER_0);
	writel(dva + 3840 * 2160 * 4, apple->regs + DISP0_SURF0 + SURF_FRAMEBUFFER_1);
	writel(SURF_FORMAT_BGRA, apple->regs + DISP0_SURF0 + SURF_FORMAT);
}

static const struct drm_plane_helper_funcs apple_plane_helper_funcs = {
	.atomic_check	= apple_plane_atomic_check,
	.atomic_disable	= apple_plane_atomic_disable,
	.atomic_update	= apple_plane_atomic_update,
};

static const struct drm_plane_funcs apple_plane_funcs = {
	.update_plane		= drm_atomic_helper_update_plane,
	.disable_plane		= drm_atomic_helper_disable_plane,
	.destroy		= drm_plane_cleanup,
	.reset			= drm_atomic_helper_plane_reset,
	.atomic_duplicate_state = drm_atomic_helper_plane_duplicate_state,
	.atomic_destroy_state	= drm_atomic_helper_plane_destroy_state,
};

uint32_t apple_plane_formats[] = {
	/* TODO: More formats */
	DRM_FORMAT_XRGB8888,
	DRM_FORMAT_ARGB8888,
};

uint64_t apple_format_modifiers[] = {
	DRM_FORMAT_MOD_LINEAR,
	DRM_FORMAT_MOD_INVALID
};

struct drm_plane *apple_plane_init(struct drm_device *dev)
{
	int ret;
	struct drm_plane *plane;

	plane = devm_kzalloc(dev->dev, sizeof(*plane), GFP_KERNEL);

	ret = drm_universal_plane_init(dev, plane, 0x1, &apple_plane_funcs,
				       apple_plane_formats,
				       ARRAY_SIZE(apple_plane_formats),
				       apple_format_modifiers,
				       DRM_PLANE_TYPE_PRIMARY, NULL);

	drm_plane_helper_add(plane, &apple_plane_helper_funcs);

	if (ret)
		return ERR_PTR(ret);

	return plane;
}

static const struct drm_crtc_funcs apple_crtc_funcs = {
	.atomic_destroy_state	= drm_atomic_helper_crtc_destroy_state,
	.atomic_duplicate_state = drm_atomic_helper_crtc_duplicate_state,
	.destroy		= drm_crtc_cleanup,
	.page_flip		= drm_atomic_helper_page_flip,
	.reset			= drm_atomic_helper_crtc_reset,
	.set_config             = drm_atomic_helper_set_config,
};

static void apple_encoder_destroy(struct drm_encoder *encoder)
{
	drm_encoder_cleanup(encoder);
}

static const struct drm_encoder_funcs apple_encoder_funcs = {
	.destroy        = apple_encoder_destroy,
};

static const struct drm_mode_config_funcs apple_mode_config_funcs = {
	.atomic_check        = drm_atomic_helper_check,
	.atomic_commit       = drm_atomic_helper_commit,
	.fb_create           = drm_gem_fb_create,
};

static const struct drm_mode_config_helper_funcs apple_mode_config_helpers = {
	.atomic_commit_tail = drm_atomic_helper_commit_tail_rpm,
};

static void apple_connector_destroy(struct drm_connector *connector)
{
	drm_connector_cleanup(connector);
}

static enum drm_connector_status
apple_connector_detect(struct drm_connector *connector, bool force)
{
	/* TODO: stub */
	return connector_status_connected;
}

static const struct drm_connector_funcs apple_connector_funcs = {
	.detect			= apple_connector_detect,
	.fill_modes		= drm_helper_probe_single_connector_modes,
	.destroy		= apple_connector_destroy,
	.reset			= drm_atomic_helper_connector_reset,
	.atomic_duplicate_state	= drm_atomic_helper_connector_duplicate_state,
	.atomic_destroy_state	= drm_atomic_helper_connector_destroy_state,
};

static int apple_connector_get_modes(struct drm_connector *connector)
{
	struct drm_device *dev = connector->dev;
	struct apple_dcp *apple = to_apple_dcp(dev);
	struct drm_display_mode *mode;

	struct drm_display_mode dummy_4k = {
		DRM_SIMPLE_MODE(3840, 2160, 1920, 1080),
	};
	struct drm_display_mode dummy_macbook = {
		DRM_SIMPLE_MODE(2560, 1600, 2560, 1600),
	};
	struct drm_display_mode *dummy = apple->forced_to_4k ? &dummy_4k : &dummy_macbook;
	if (!apple->forced_to_4k) {
		u32 resolution = readl(apple->regs + 0x100c0);
		u32 resx = resolution >> 16;
		u32 resy = resolution & 0xffff;
		dummy->hdisplay = dummy->hsync_start =
			dummy->hsync_end = dummy->htotal = resx;
		dummy->vdisplay = dummy->vsync_start =
			dummy->vsync_end = dummy->vtotal = resy;
	}

	dummy->clock = 60 * dummy->hdisplay * dummy->vdisplay / 1000L;
	drm_mode_set_name(dummy);

	mode = drm_mode_duplicate(dev, dummy);
	if (!mode) {
		DRM_ERROR("Failed to create a new display mode\n");
		return 0;
	}

	drm_mode_probed_add(connector, mode);
	return 1;
}

static int apple_connector_mode_valid(struct drm_connector *connector,
					   struct drm_display_mode *mode)
{
	/* STUB */
	return MODE_OK;
}

static const
struct drm_connector_helper_funcs apple_connector_helper_funcs = {
	.get_modes	= apple_connector_get_modes,
	.mode_valid	= apple_connector_mode_valid,
};

static void apple_crtc_atomic_enable(struct drm_crtc *crtc,
				     struct drm_atomic_state *state)
{
	struct apple_dcp *apple = to_apple_dcp(crtc->dev);
	apple_find_backlight(apple);

	if (apple->backlight) {
		apple->backlight->props.power = FB_BLANK_UNBLANK;
		backlight_update_status(apple->backlight);
	}
	/* TODO */
}

static void apple_crtc_atomic_disable(struct drm_crtc *crtc,
				      struct drm_atomic_state *state)
{
	struct apple_dcp *apple = to_apple_dcp(crtc->dev);
	apple_find_backlight(apple);

	if (apple->backlight) {
		apple->backlight->props.power = FB_BLANK_POWERDOWN;
		backlight_update_status(apple->backlight);
	}
	/* TODO */
}

static void apple_crtc_atomic_begin(struct drm_crtc *crtc,
				    struct drm_atomic_state *state)
{
	/* TODO */
}

static void apple_crtc_atomic_flush(struct drm_crtc *crtc,
				    struct drm_atomic_state *state)
{
	/* TODO */
}

static const struct drm_crtc_helper_funcs apple_crtc_helper_funcs = {
	.atomic_begin	= apple_crtc_atomic_begin,
	.atomic_flush	= apple_crtc_atomic_flush,
	.atomic_enable	= apple_crtc_atomic_enable,
	.atomic_disable	= apple_crtc_atomic_disable,
};

static void apple_dpms(struct drm_encoder *encoder, int mode)
{
	struct apple_dcp *apple = to_apple_dcp(encoder->dev);

	apple_find_backlight(apple);

	if (apple->backlight) {
		apple->backlight->props.power = mode == DRM_MODE_DPMS_ON ?
					 FB_BLANK_UNBLANK : FB_BLANK_POWERDOWN;
		backlight_update_status(apple->backlight);
	}
}

static struct drm_encoder_helper_funcs apple_encoder_helper_funcs = {
	.dpms = apple_dpms,
};

extern int apple_dcp_reached_hardware_boot(struct mbox_chan *chan,
					   struct device *dev);

static void apple_handle_d116(struct apple_dcp *apple);

static void apple_dcp_receive_data(struct mbox_client *cl, void *msg)
{
	struct apple_drm_stream *stream = container_of(cl, struct apple_drm_stream, cl);
	struct apple_dcp *apple = stream->self;
	int streamno = stream - apple->stream;
	unsigned long flags;

	switch (streamno) {
	case STREAM_COMMAND:
	case STREAM_NESTED_COMMAND:
		complete_all(&stream->complete);
		break;

	case STREAM_ASYNC:
	case STREAM_CALLBACK:
		printk("callback: %s\n", msg + 12);
		spin_lock_irqsave(&apple->lock, flags);
		struct list_msg *list_msg = devm_kzalloc(apple->drm.dev, sizeof(*list_msg), GFP_KERNEL);
		list_msg->msg = msg;
		list_add(&list_msg->list, &apple->callback_messages);
		INIT_WORK(&apple->work_callback, apple_dcp_work_func);
		schedule_work(&apple->work_callback);
		spin_unlock_irqrestore(&apple->lock, flags);
		break;
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
	u32 in[13];
	u32 out[2];
} __attribute__((packed));
struct apple_dcp_msg_start_swap {
	struct apple_dcp_msg_header header;
	u32 in[13];
	u32 out[2];
} __attribute__((packed));
struct apple_dcp_msg_set_digital_mode {
	struct apple_dcp_msg_header header;
	u32 in[13];
	u32 out[2];
} __attribute__((packed));

#define INIT_APPLE_DCP_MSG(ptr, code_str)  do {			\
		(ptr)->header.code = FOURCC(code_str);		\
		(ptr)->header.len_input = sizeof((ptr)->in);	\
		(ptr)->header.len_output = sizeof((ptr)->out);	\
	} while (0)

static int apple_dcp_init(struct apple_dcp *apple)
{
	struct apple_dcp_msg_init a401 = {};
	struct apple_dcp_msg_void a357 = {};
	struct apple_dcp_msg_void_int a443 = {};
	struct apple_dcp_msg_void a029 = {};
	struct apple_dcp_msg_int_void a463 = {
		.in = 1,
	};
	struct apple_dcp_msg_void_int a460 = {};
	struct apple_dcp_msg_color_remap_mode a447 = {
		.in = { 6, },
	};
	struct apple_dcp_msg_update_notify_clients a034 = {
		.in = { 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, }
	};
	struct apple_dcp_msg_void a454 = {};
	struct apple_dcp_msg_void_int a469 = {};
	struct apple_dcp_msg_void_int a411 = {};
	struct apple_dcp_msg_set_digital_mode a412 = {
		.in = { 0x59, 0x43, },
	};

	struct apple_dcp_msg_begin_swap *a407 = kzalloc(sizeof *a407, GFP_KERNEL);
	struct apple_dcp_msg_start_swap *a408 = kzalloc(sizeof *a408, GFP_KERNEL);
	int delay = 2000;
	INIT_APPLE_DCP_MSG(&a401, "A401");
	INIT_APPLE_DCP_MSG(&a357, "A357");
	INIT_APPLE_DCP_MSG(&a443, "A443");
	INIT_APPLE_DCP_MSG(&a029, "A029");
	INIT_APPLE_DCP_MSG(&a463, "A463");
	INIT_APPLE_DCP_MSG(&a460, "A460");
	INIT_APPLE_DCP_MSG(&a447, "A447");
	INIT_APPLE_DCP_MSG(&a034, "A034");
	INIT_APPLE_DCP_MSG(&a454, "A454");
	INIT_APPLE_DCP_MSG(&a411, "A411");

	printk("zeroth call\n");
	msleep(delay);
	printk("first call\n");
	apple_fw_call(apple, &a401.header, STREAM_COMMAND);
	msleep(delay);
	apple_fw_call(apple, &a357.header, STREAM_COMMAND);
	msleep(delay);
	apple_fw_call(apple, &a443.header, STREAM_COMMAND);
	msleep(delay);
	apple_fw_call(apple, &a029.header, STREAM_COMMAND);
	msleep(delay);
	apple_fw_call(apple, &a463.header, STREAM_COMMAND);
	msleep(delay);
	apple_fw_call(apple, &a460.header, STREAM_COMMAND);
	msleep(delay);
	apple_fw_call(apple, &a447.header, STREAM_COMMAND);
	msleep(delay);
	apple_fw_call(apple, &a034.header, STREAM_COMMAND);
	msleep(delay);
	apple_fw_call(apple, &a454.header, STREAM_COMMAND);
	msleep(delay);
	apple_fw_call(apple, &a411.header, STREAM_COMMAND);
	msleep(delay);

	msleep(delay);
	while (true) {
	msleep(delay);
		apple_fw_call(apple, &a407->header, STREAM_COMMAND);
	msleep(delay);
		apple_fw_call(apple, &a412.header, STREAM_COMMAND);
	msleep(delay);
		msleep(delay);
	msleep(delay);
		apple_fw_call(apple, &a408->header, STREAM_COMMAND);
	msleep(delay);
		delay += 500;
	msleep(delay);
	}

	return 0;
}

static int apple_dcp_probe(struct platform_device *pdev)
{
	struct apple_dcp *apple;
	int ret = 0, i;

	apple = devm_drm_dev_alloc(&pdev->dev, &apple_drm_driver,
				   struct apple_dcp, drm);
	if (IS_ERR(apple))
		return PTR_ERR(apple);

	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
	if (ret)
		return ret;

	for (i = 0; i < N_STREAMS; i++) {
		apple->stream[i].self = apple;
		apple->stream[i].cl.dev = &pdev->dev;
		apple->stream[i].cl.rx_callback = apple_dcp_receive_data;
		apple->stream[i].dcp = mbox_request_channel(&apple->stream[i].cl, i);
		if (IS_ERR(apple->stream[i].dcp)) {
			ret = PTR_ERR(apple->stream[i].dcp);
			goto err_unload;
		}
		init_completion(&apple->stream[i].complete);
	}

	INIT_LIST_HEAD(&apple->rbufs);
	mutex_init(&apple->mutex);

	apple_dcp = apple;
	of_platform_populate(pdev->dev.of_node, NULL, NULL, &pdev->dev);

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

MODULE_DESCRIPTION("Apple Display Controller DRM driver");
MODULE_LICENSE("GPL v2");
