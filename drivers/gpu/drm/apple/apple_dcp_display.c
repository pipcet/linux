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

#define N_STREAMS		4
#define STREAM_COMMAND		0 /* ping pong: receive msg, send modified msg */
#define STREAM_CALLBACK		1 /* pong ping: send msg, receive modified msg */
#define STREAM_ASYNC		2 /* pong ping */
#define STREAM_NESTED_COMMAND	3 /* ping pong */

struct apple_dcp_display;
struct apple_dcp_display {
	struct device		*dev;
	struct apple_dcp	*dcp;
};

uint32_t apple_plane_formats[] = {
	DRM_FORMAT_ARGB8888,
};

uint64_t apple_format_modifiers[] = {
	DRM_FORMAT_MOD_LINEAR,
	DRM_FORMAT_MOD_INVALID
};

/* It's probably a good idea to specify pptr, because one day we might
 * have a way of unloading this driver. */
dma_addr_t apple_dcp_display_alloc_buffer(struct apple_dcp_display *apple,
					  size_t size, void **pptr)
{
	dma_addr_t ret = 0;
	void *ptr = dma_alloc_coherent(apple->dev, size, &ret, GFP_KERNEL);

	if (pptr)
		*pptr = ptr;

	return ret;
}
EXPORT_SYMBOL(apple_dcp_display_alloc_buffer);

static int apple_dcp_display_probe(struct platform_device *pdev)
{
	struct apple_dcp_display *apple;
	int ret;

	apple = devm_kzalloc(&pdev->dev, sizeof *apple, GFP_KERNEL);
	if (!apple)
		return -ENOMEM;

	apple->dev = &pdev->dev;
	apple->dcp = platform_get_drvdata(to_platform_device(pdev->dev.parent));

	ret = dma_set_mask_and_coherent(apple->dev, DMA_BIT_MASK(32));
	if (ret)
		return ret;

	of_platform_populate(pdev->dev.of_node, NULL, NULL, &pdev->dev);

	apple_dcp_set_display(apple->dcp, &pdev->dev);

	return 0;
}

static int apple_dcp_display_remove(struct platform_device *pdev)
{
	return -EBUSY;
}

static const struct of_device_id of_match[] = {
	{ .compatible = "apple,dcp-display" },
	{}
};
MODULE_DEVICE_TABLE(of, of_match);

static struct platform_driver apple_platform_driver = {
	.probe	= apple_dcp_display_probe,
	.remove	= apple_dcp_display_remove,
	.driver	= {
		.name = "apple-dcp-display",
		.of_match_table	= of_match,
	},
};

module_platform_driver(apple_platform_driver);

MODULE_DESCRIPTION("Apple Display Controller DRM driver");
MODULE_LICENSE("GPL v2");
