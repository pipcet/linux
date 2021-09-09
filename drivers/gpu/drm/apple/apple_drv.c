// SPDX-License-Identifier: GPL-2.0-only
/* Horribly mutilated by Pip Cet <pipcet@gmail.com> */
/* Copyright 2021 Alyssa Rosenzweig <alyssa@rosenzweig.io> */
/* Based on meson driver which is
 * Copyright (C) 2016 BayLibre, SAS
 * Author: Neil Armstrong <narmstrong@baylibre.com>
 * Copyright (C) 2015 Amlogic, Inc. All rights reserved.
 * Copyright (C) 2014 Endless Mobile
 */

#include <linux/apple-asc.h>
#include <linux/module.h>
#include <linux/backlight.h>
#include <linux/clk.h>
#include <linux/component.h>
#include <linux/delay.h>
#include <linux/of_device.h>
#include <linux/of_graph.h>
#include <linux/of_reserved_mem.h>
#include <linux/pm_runtime.h>
#include <linux/debugfs.h>
#include <linux/dma-mapping.h>
#include <linux/kvbox.h>

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

struct apple_drm_private {
	struct drm_device	drm;
	bool			forced_to_4k;
	struct mbox_client	cl;
	struct mbox_chan *	dcp;
	struct kvbox		kvbox;
	struct work_struct	work;
	struct apple_dcp_mbox_msg *msg;
	spinlock_t		lock;
	bool			write;
	struct kvbox_prop *	prop;
	void __iomem		*regs;

	u32 *			regdump;
	struct backlight_device *backlight;
};

static int apple_match_backlight(struct device *dev, void *ptr)
{
	struct apple_drm_private *apple = ptr;
	struct backlight_device *backlight;

	backlight = devm_of_find_backlight(dev);
	if (!IS_ERR(backlight))
		apple->backlight = backlight;

	return 0;
}

static void apple_find_backlight(struct apple_drm_private *apple)
{
	if (!apple->backlight) {
		device_for_each_child(apple->drm.dev, apple, apple_match_backlight);
	}
}

#define DCP_LATE_INIT_SIGNAL 0x41343031
#define DCP_SET_DIGITAL_MODE 0x41343132
#define DCP_APPLY_PROPERTY 0x41333532 /* A352: applyProperty(unsigned int, unsigned int) */

#define REGDUMP_START 0x10000
#define REGDUMP_END   0x34000

static int apple_regdump_create(struct apple_drm_private *apple)
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

static int apple_regdump_replay(struct apple_drm_private *apple)
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

static int apple_external(struct apple_drm_private *apple)
{
	struct apple_dcp_mbox_msg *msg = devm_kzalloc(apple->drm.dev,
						      sizeof(*msg) + 0x100,
						      GFP_KERNEL);
	const u32 mode_args[] = { 0x59, 0x43 };
	int ret;

	if (!msg)
		return -ENOMEM;

	ret = apple_regdump_create(apple);
	if (ret < 0)
		return ret;

	msg->mbox.payload = 0x202; /* message type 2, command context */
	msg->dcp.code = DCP_LATE_INIT_SIGNAL;
	msg->dcp.len_input = 8;
	msg->dcp.len_output = 4;
	memcpy(msg->dcp_data, mode_args, sizeof(mode_args));

	ret = apple_dcp_transaction(apple->dcp, msg);
	devm_kfree(apple->drm.dev, msg);
	if (ret < 0)
		return ret;

	msleep(10000);

	ret = apple_regdump_replay(apple);

	if (ret < 0)
		return ret;

	writel(4 * 3840, apple->regs + 0x100a8);
	writel(3840, apple->regs + 0x100ac);
	writel(0xf000870, apple->regs + 0x100c0);
	writel(0xf000870, apple->regs + 0x100c4);
	writel(0xf000870, apple->regs + 0x100d0);
	writel(0xf000870, apple->regs + 0x10118);
	writel(0xf000870, apple->regs + 0x10128);

	return 0;
}

static int apple_switch_4k(struct apple_drm_private *apple)
{
	struct apple_dcp_mbox_msg *msg = devm_kzalloc(apple->drm.dev,
						      sizeof(*msg) + 0x100,
						      GFP_KERNEL);
	const u32 mode_args[] = { 0x59, 0x43 };
	int ret;

	if (!msg)
		return -ENOMEM;

	ret = apple_regdump_create(apple);
	if (ret < 0)
		return ret;

	msg->mbox.payload = 0x202; /* message type 2, command context */
	msg->dcp.code = DCP_SET_DIGITAL_MODE;
	msg->dcp.len_input = 8;
	msg->dcp.len_output = 4;
	memcpy(msg->dcp_data, mode_args, sizeof(mode_args));

	ret = apple_dcp_transaction(apple->dcp, msg);
	devm_kfree(apple->drm.dev, msg);
	if (ret < 0)
		return ret;

	msleep(10000);

	ret = apple_regdump_replay(apple);

	if (ret < 0)
		return ret;

	writel(4 * 3840, apple->regs + 0x100a8);
	writel(3840, apple->regs + 0x100ac);
	writel(0xf000870, apple->regs + 0x100c0);
	writel(0xf000870, apple->regs + 0x100c4);
	writel(0xf000870, apple->regs + 0x100d0);
	writel(0xf000870, apple->regs + 0x10118);
	writel(0xf000870, apple->regs + 0x10128);

	return 0;
}

static void apple_write_work_func(struct work_struct *work)
{
	struct apple_drm_private *apple = container_of(work, struct apple_drm_private, work);
	unsigned long flags;

	apple_dcp_transaction(apple->dcp, apple->msg);
	spin_lock_irqsave(&apple->lock, flags);
	kfree(apple->msg);
	apple->msg = NULL;
	apple->prop = NULL;
	spin_unlock_irqrestore(&apple->lock, flags);
}

static int apple_drm_write(struct kvbox *kvbox, struct kvbox_prop *prop)
{
	struct apple_drm_private *apple = kvbox->priv;
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

#define to_apple_drm_private(x) \
	container_of(x, struct apple_drm_private, drm)

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
	/* TODO */
}

static void apple_plane_atomic_update(struct drm_plane *plane,
				      struct drm_atomic_state *state)
{
	struct apple_drm_private *apple = to_apple_drm_private(plane->dev);
	struct drm_plane_state *plane_state;
	struct drm_framebuffer *fb;
	dma_addr_t dva;

	plane_state = drm_atomic_get_new_plane_state(state, plane);
	fb = plane_state->fb;
	dva = drm_fb_cma_get_gem_addr(fb, plane_state, 0);

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
	struct apple_drm_private *apple = to_apple_drm_private(dev);
	struct drm_display_mode *mode;

	struct drm_display_mode dummy_4k = {
		DRM_SIMPLE_MODE(3840, 2160, 1920, 1080),
	};
	struct drm_display_mode dummy_macbook = {
		DRM_SIMPLE_MODE(2560, 1600, 2560, 1600),
	};
	struct drm_display_mode *dummy = apple->forced_to_4k ? &dummy_4k : &dummy_macbook;
	u32 resolution = readl(apple->regs + 0x100c0);
	u32 resx = resolution >> 16;
	u32 resy = resolution & 0xffff;
	dummy->hdisplay = dummy->hsync_start =
		dummy->hsync_end = dummy->htotal = resx;
	dummy->vdisplay = dummy->vsync_start =
		dummy->vsync_end = dummy->vtotal = resy;

	dummy->clock = 60 * dummy->hdisplay * dummy->vdisplay;
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
	struct apple_drm_private *apple = to_apple_drm_private(crtc->dev);
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
	struct apple_drm_private *apple = to_apple_drm_private(crtc->dev);
	apple_find_backlight(apple);

	printk("atomic_disable %p\n", apple->backlight);
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
	struct apple_drm_private *apple = to_apple_drm_private(encoder->dev);

	printk("apple_dpms %d\n", mode);
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

static int apple_platform_probe(struct platform_device *pdev)
{
	struct apple_drm_private *apple;
	struct drm_plane *plane;
	struct drm_crtc *crtc;
	struct drm_encoder *encoder;
	struct drm_connector *connector;
	int ret;

	apple = devm_drm_dev_alloc(&pdev->dev, &apple_drm_driver,
				   struct apple_drm_private, drm);
	if (IS_ERR(apple))
		return PTR_ERR(apple);

	INIT_WORK(&apple->work, apple_write_work_func);
	if (of_property_read_bool(pdev->dev.of_node, "switch-to-4k")) {
		apple->forced_to_4k = true;
	}
	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));

	if (ret)
		return ret;

	apple->regs = devm_platform_ioremap_resource(pdev, 0);

	if (!apple->regs)
		return -ENODEV;

	apple->cl.dev = &pdev->dev;
	apple->dcp = mbox_request_channel(&apple->cl, 0);
	if (IS_ERR(apple->dcp)) {
		ret = PTR_ERR(apple->dcp);
		goto err_unload;
	}

	/*
	 * Remove early framebuffers (ie. simplefb). The framebuffer can be
	 * located anywhere in RAM
	 */
	ret = drm_aperture_remove_framebuffers(false, &apple_drm_driver);
	if (ret)
		return ret;

	ret = drmm_mode_config_init(&apple->drm);
	if (ret)
		goto err_unload;

	apple->drm.mode_config.max_width = 3840;
	apple->drm.mode_config.max_height = 2160;
	apple->drm.mode_config.funcs = &apple_mode_config_funcs;
	apple->drm.mode_config.helper_private = &apple_mode_config_helpers;

	plane = apple_plane_init(&apple->drm);

	if (IS_ERR(plane)) {
		ret = PTR_ERR(plane);
		goto err_unload;
	}

	crtc = devm_kzalloc(&pdev->dev, sizeof(*crtc), GFP_KERNEL);
	ret = drm_crtc_init_with_planes(&apple->drm, crtc, plane, NULL,
					&apple_crtc_funcs, NULL);
	if (ret)
		goto err_unload;


	drm_crtc_helper_add(crtc, &apple_crtc_helper_funcs);

	encoder = devm_kzalloc(&pdev->dev, sizeof(*encoder), GFP_KERNEL);
	if (!encoder) {
		ret = -ENOMEM;
		goto err_unload;
	}
	encoder->possible_crtcs = drm_crtc_mask(crtc);
	ret = drm_encoder_init(&apple->drm, encoder, &apple_encoder_funcs,
			       DRM_MODE_ENCODER_TMDS /* XXX */, "apple_hdmi");
	if (ret)
		goto err_unload;

	drm_encoder_helper_add(encoder, &apple_encoder_helper_funcs);

	connector = devm_kzalloc(&pdev->dev, sizeof(*connector), GFP_KERNEL);

	drm_connector_helper_add(connector,
			&apple_connector_helper_funcs);

	ret = drm_connector_init(&apple->drm, connector, &apple_connector_funcs,
				 DRM_MODE_CONNECTOR_HDMIA);
	if (ret)
		goto err_unload;

	ret = drm_connector_attach_encoder(connector, encoder);
	if (ret)
		goto err_unload;

	drm_mode_config_reset(&apple->drm); // TODO: needed?

	ret = drm_dev_register(&apple->drm, 0);
	if (ret)
		goto err_unload;

	drm_fbdev_generic_setup(&apple->drm, 32);

	apple->kvbox.dev = &pdev->dev;
	apple->kvbox.ops = &apple_drm_kvbox_ops;
	spin_lock_init(&apple->lock);
	apple->kvbox.priv = apple;
	INIT_LIST_HEAD(&apple->kvbox.requests);
	kvbox_register(&apple->kvbox);

	if (of_property_read_bool(pdev->dev.of_node, "external-interface")) {
		ret = apple_external(apple);
		if (ret)
			return ret;
	}

	if (of_property_read_bool(pdev->dev.of_node, "switch-to-4k")) {
		ret = apple_switch_4k(apple);
		if (ret)
			return ret;
	}

	of_platform_populate(pdev->dev.of_node, NULL, NULL, &pdev->dev);

	return 0;

err_unload:
	drm_dev_put(&apple->drm);
	return ret;
}

static int apple_platform_remove(struct platform_device *pdev)
{
	struct drm_device *drm = platform_get_drvdata(pdev);

	if (drm)
		drm_dev_unregister(drm);

	return 0;
}

static const struct of_device_id of_match[] = {
	{ .compatible = "apple,t8103-disp" },
	{}
};
MODULE_DEVICE_TABLE(of, of_match);

static struct platform_driver apple_platform_driver = {
	.probe		= apple_platform_probe,
	.remove	= apple_platform_remove,
	.driver	= {
		.name = "apple",
		.of_match_table	= of_match,
	},
};

module_platform_driver(apple_platform_driver);

MODULE_DESCRIPTION("Apple Display Controller DRM driver");
MODULE_LICENSE("GPL v2");
