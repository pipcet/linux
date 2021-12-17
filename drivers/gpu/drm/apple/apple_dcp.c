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
	struct drm_device drm;
	struct device *dev;
	struct mutex mutex;
	bool forced_to_4k;
	struct apple_dcp_stream stream[N_STREAMS];
	struct kvbox kvbox;
	struct work_struct work;
	struct work_struct work_callback;
	struct apple_dcp_mbox_msg *msg;
	spinlock_t lock;
	bool write;
	struct kvbox_prop *prop;
	void __iomem *regs;
	dma_addr_t dummy_buffer;

	void *va_fb;
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

static u64 apple_get_fb_dva(struct apple_dcp *dcp)
{
	struct device *dev = dcp->fb;
	static dma_addr_t dma_addr;
	void *va;
	int i;

	BUG_ON(!dcp->fb);

	if (!dma_addr) {
		dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32));
		/* XXX work out why dma_alloc_coherent doesn't work here. */
		va = dma_alloc_noncoherent(dev, 32<<20, &dma_addr, DMA_TO_DEVICE, GFP_KERNEL);
		memset(va, 255, (32<<20));
		struct iommu_domain *domain = iommu_get_domain_for_dev(dcp->display);
		size_t off;
		extern u64 get_fb_physical_address(void);
		u64 base = get_fb_physical_address();
		for (off = 0; off < (32<<20); off += 16384)
			iommu_map(domain, 0xa0000000+off, base+off, 16384, IOMMU_READ|IOMMU_WRITE);
		memset(va, 255, (32<<20));
		dma_addr = 0xa0000000;
		*(u64 *)phys_to_virt(0x9fff78280) =
			*(u64 *)phys_to_virt(0x9fff48280);
		dcp->va_fb = va;
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
		apple->backlight = of_find_backlight_by_node(apple->dev->of_node);
		if (IS_ERR(apple->backlight))
			apple->backlight = NULL;
	}

	if (!apple->backlight) {
		apple->backlight = devm_of_find_backlight(apple->dev);
		if (IS_ERR(apple->backlight))
			apple->backlight = NULL;
	}

	if (!apple->backlight) {
		device_for_each_child(apple->dev, apple, apple_match_backlight);
	}
}

static int apple_fw_call(struct apple_dcp *apple,
			 struct apple_dcp_msg_header *header,
			 int stream)
{
	struct apple_dcp_msg *msg = container_of(header, struct apple_dcp_msg, header);
	int ret = 0;

	mutex_lock(&apple->mutex);
	reinit_completion(&apple->stream[stream].complete);
	mbox_send_message(apple->stream[stream].dcp, msg);
	wait_for_completion(&apple->stream[stream].complete);
	mutex_unlock(&apple->mutex);

	return ret;
}

static void apple_dcp_single_callback(struct apple_dcp *dcp, struct apple_dcp_msg *msg)
{
	struct apple_dcp_callback *callback = apple_dcp_callbacks;

	while (callback < apple_dcp_callbacks + sizeof(apple_dcp_callbacks)/sizeof(apple_dcp_callbacks[0])) {
		if (callback->fourcc == msg->header.code) {
			callback_return_zero(dcp, msg);
			callback->callback(dcp, msg);
			return;
		}
		callback++;
	}

	dev_err(dcp->dev, "callback %c%c%c%c not found!\n",
		FOURCC_CHARS(msg->header.code));
}

static void apple_dcp_work_func(struct work_struct *work)
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
	msg->dcp.code = 0 /* DCP_APPLY_PROPERTY */;
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
	dev_info(apple->dev, "disable: mapping dummy buffer\n");
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
		dev_info(apple->dev, "update: mapping dummy buffer\n");
		dva = apple->dummy_buffer;
	}
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

static int dcp_command_debugfs_show(struct seq_file *s, void *ptr)
{
	struct apple_dcp *dcp = s->private;
	struct completion c;
	void *buf;
	int ret;
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

static ssize_t dcp_command_debugfs_write(struct file *file,
					 const char __user *user_buf,
					 size_t size, loff_t *ppos)
{
	struct seq_file *s = file->private_data;
	struct apple_dcp *dcp = s->private;
	struct completion c;
	void *buf;
	int ret;
	struct apple_dcp_msg *msg = devm_kzalloc(dcp->dev, size, GFP_KERNEL);
	struct list_msg *list_msg;

	if (size < 12) {
		devm_kfree(dcp->dev, msg);
		return -EINVAL;
	}

	if (copy_from_user(msg, user_buf, size)) {
		devm_kfree(dcp->dev, msg);
		return -EFAULT;
	}

	if (apple_dcp_msg_size(&msg->header) != size) {
		devm_kfree(dcp->dev, msg);
		return -EINVAL;
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

DEFINE_SHOW_ATTRIBUTE(dcp_command_debugfs);
static const struct file_operations real_dcp_command_debugfs_fops = {
	.owner = THIS_MODULE,
	.open = dcp_command_debugfs_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = dcp_command_debugfs_write,
};

static void apple_dcp_debugfs_init_command(struct apple_dcp *dcp, struct dentry *dentry)
{
	debugfs_create_file("command", 0600, dentry, dcp, &real_dcp_command_debugfs_fops);
}

static int apple_dcp_debugfs_init(struct apple_dcp *dcp)
{
	struct dentry *dentry;

	dentry = debugfs_create_dir("dcp", NULL);

	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	apple_dcp_debugfs_init_command(dcp, dentry);

	return 0;
}

extern int apple_dcp_reached_hardware_boot(struct mbox_chan *chan,
					   struct device *dev);

static void apple_handle_d116(struct apple_dcp *apple);

static void apple_dcp_receive_data(struct mbox_client *cl, void *msg)
{
	struct apple_dcp_stream *stream =
		container_of(cl, struct apple_dcp_stream, cl);
	struct apple_dcp *apple = stream->self;
	int streamno = stream - apple->stream;

	switch (streamno) {
	case STREAM_COMMAND:
	case STREAM_NESTED_COMMAND:
		complete_all(&stream->complete);
		break;

	case STREAM_ASYNC:
	case STREAM_CALLBACK: {
		struct list_msg *list_msg = devm_kzalloc(apple->dev, sizeof(*list_msg), GFP_KERNEL);
		char *str = msg;
		list_msg->msg = msg;
		list_msg->stream = streamno;
		list_add(&list_msg->list, &apple->callback_messages);
		schedule_work(&apple->work_callback);
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

struct apple_dcp_msg_set_power_state {
	struct apple_dcp_msg_header header;
	u32 in[3];
	u32 out[2];
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

#define INIT_APPLE_DCP_MSG(ptr, code_str)  do {			\
		(ptr)->header.code = FOURCC(code_str);		\
		(ptr)->header.len_input = sizeof((ptr)->in);	\
		(ptr)->header.len_output = sizeof((ptr)->out);	\
	} while (0)

static int apple_dcp_init(struct apple_dcp *apple)
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
	struct apple_dcp_msg_set_digital_mode a412 = {
		.in = { 0x59, 0x43, },
	};
	struct apple_dcp_msg_set_power_state a468 = {
		.in = { 1, },
	};

	struct apple_dcp_msg_begin_swap *a407 = kzalloc(sizeof *a407, GFP_KERNEL);
	struct apple_dcp_msg_start_swap *a408 = kzalloc(sizeof *a408, GFP_KERNEL);
	int delay = 2000;
	u32 surface_id = 3; /* this works... */

	INIT_APPLE_DCP_MSG(&a000, "A000");
	INIT_APPLE_DCP_MSG(&a029, "A029");
	INIT_APPLE_DCP_MSG(&a034, "A034");
	INIT_APPLE_DCP_MSG(&a357, "A357");
	INIT_APPLE_DCP_MSG(&a401, "A401");
	INIT_APPLE_DCP_MSG(&a411, "A411");
	INIT_APPLE_DCP_MSG(&a412, "A412");
	INIT_APPLE_DCP_MSG(&a426, "A426");
	INIT_APPLE_DCP_MSG(&a443, "A443");
	INIT_APPLE_DCP_MSG(&a447, "A447");
	INIT_APPLE_DCP_MSG(&a454, "A454");
	INIT_APPLE_DCP_MSG(&a460, "A460");
	INIT_APPLE_DCP_MSG(&a463, "A463");
	INIT_APPLE_DCP_MSG(&a468, "A468");
	INIT_APPLE_DCP_MSG(&a469, "A469");

	apple_fw_call(apple, &a401.header, STREAM_COMMAND);
	apple_fw_call(apple, &a357.header, STREAM_COMMAND);
	apple_fw_call(apple, &a443.header, STREAM_COMMAND);
	apple_fw_call(apple, &a029.header, STREAM_COMMAND);
	apple_fw_call(apple, &a463.header, STREAM_COMMAND);
	apple_fw_call(apple, &a460.header, STREAM_COMMAND);
	apple_fw_call(apple, &a426.header, STREAM_COMMAND);
	apple_fw_call(apple, &a447.header, STREAM_COMMAND);
	apple_fw_call(apple, &a034.header, STREAM_COMMAND);
	apple_fw_call(apple, &a454.header, STREAM_COMMAND);
	apple_fw_call(apple, &a469.header, STREAM_COMMAND);
	apple_fw_call(apple, &a411.header, STREAM_COMMAND);
	apple_fw_call(apple, &a468.header, STREAM_COMMAND);

	//apple_fw_call(apple, &a000.header, STREAM_COMMAND);

	INIT_APPLE_DCP_MSG(a407, "A407");
	INIT_APPLE_DCP_MSG(a408, "A408");
	a407->in.addr = 0xfffffe1667ba4a00;
	a407->in.flags = 0x0000010000000000;
	while (delay <= 3000) {
		u32 swap_id;
		apple_fw_call(apple, &a407->header, STREAM_COMMAND);
		swap_id = a407->out.swap_id;
		msleep(delay);
		a408->in.swaprec.flags[0] = 0x861202;
		a408->in.swaprec.flags[2] = 0x04;
		a408->in.swaprec.swap_id = swap_id;
		a408->in.swaprec.surf_ids[0] = surface_id;
		a408->in.swaprec.src_rect[0].width = 1920;
		a408->in.swaprec.src_rect[0].height = 1080;
		a408->in.swaprec.surf_flags[0] = 1;
		a408->in.swaprec.dst_rect[0].width = 3840;
		a408->in.swaprec.dst_rect[0].height = 2160;
		a408->in.swaprec.swap_enabled = 0x80000007;
		a408->in.swaprec.swap_completed = 0x80000007;
		a408->in.surf_addr[0] = apple_get_fb_dva(apple);
		memset(apple->va_fb, 255, 32<<20);
		a408->in.surface[0].format = 0x42475241;
		a408->in.surface[0].unk2[0] = 0x0d;
		a408->in.surface[0].unk2[1] = 0x01;
		a408->in.surface[0].stride = 1920 * 4;
		a408->in.surface[0].pix_size = 4;
		a408->in.surface[0].pel_w = 1;
		a408->in.surface[0].pel_h = 1;
		a408->in.surface[0].width = 1920;
		a408->in.surface[0].height = 1080;
		a408->in.surface[0].buf_size = 1920 * 1080 * 4;
		a408->in.surface[0].surface_id = surface_id;
		a408->in.surface[0].has_comp = 1;
		a408->in.surface[0].has_planes = 1;
		a408->header.len_input = 0xb64;
		memset((void *)a408 + 0xb6b, 1, 3);
		apple_fw_call(apple, &a412.header, STREAM_COMMAND);
		msleep(delay);
		apple_fw_call(apple, &a408->header, STREAM_COMMAND);
		delay += 250;
	}
	msleep(10000);
	memset(apple->va_fb, 255, 32<<20);

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

	apple->dev = &pdev->dev;

	apple->dva_display = 0xb0000000;
	apple->dva_framebuffer = 0xa0000000;
	ret = dma_set_mask_and_coherent(apple->dev, DMA_BIT_MASK(32));
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
	INIT_LIST_HEAD(&apple->callback_messages);
	INIT_LIST_HEAD(&apple->debugfs_messages);
	INIT_WORK(&apple->work_callback, apple_dcp_work_func);
	mutex_init(&apple->mutex);
	spin_lock_init(&apple->lock);

	apple_dcp = apple;
	of_platform_populate(pdev->dev.of_node, NULL, NULL, &pdev->dev);

	apple_dcp_debugfs_init(apple);

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
