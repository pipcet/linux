// SPDX-License-Identifier: GPL-2.0+ OR MIT
/*
 * Driver for Apple M1 WDT
 *
 * The Apple M1 WDT exposes a simple watchdog timer interface; there
 * are also additional, more complicated features that haven't been
 * fully reverse-engineered.
 *
 * This driver requires a clock, such as the fixed refclk at 24 MHz.
 *
 * Hardware documentation:
 *
 *   https://github.com/AsahiLinux/docs/wiki/HW:WDT
 *
 * Copyright (C) 2021 Pip Cet <pipcet@gmail.com>
 */

#include <linux/clk.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/watchdog.h>

#define WDT_COUNT		0x10
#define WDT_COMPARATOR		0x14
#define WDT_CONTROL		0x1c
#define   WDT_CONTROL_TRIGGER	BIT(2)

struct apple_wdt {
	void __iomem *reg;
	struct clk *clk;
	u32 rate;
};

static int apple_wdt_start(struct watchdog_device *w)
{
	struct apple_wdt *wdt = watchdog_get_drvdata(w);

	writel(0, wdt->reg + WDT_COUNT);
	writel(U32_MAX, wdt->reg + WDT_COMPARATOR);
	writel(WDT_CONTROL_TRIGGER, wdt->reg + WDT_CONTROL);

	return 0;
}

static int apple_wdt_stop(struct watchdog_device *w)
{
	struct apple_wdt *wdt = watchdog_get_drvdata(w);

	writel(0, wdt->reg + WDT_COUNT);
	writel(U32_MAX, wdt->reg + WDT_COMPARATOR);
	writel(0, wdt->reg + WDT_CONTROL);

	return 0;
}

static int apple_wdt_ping(struct watchdog_device *w)
{
	struct apple_wdt *wdt = watchdog_get_drvdata(w);

	writel(0, wdt->reg + WDT_COUNT);

	return 0;
}

static int apple_wdt_set_timeout(struct watchdog_device *w, unsigned int s)
{
	struct apple_wdt *wdt = watchdog_get_drvdata(w);
	u64 comparator;

	comparator = mul_u32_u32(wdt->rate, s);
	if (comparator > U32_MAX)
		comparator = U32_MAX;

	writel(comparator, wdt->reg + WDT_COMPARATOR);

	return 0;
}

static unsigned int apple_wdt_get_timeleft(struct watchdog_device *w)
{
	struct apple_wdt *wdt = watchdog_get_drvdata(w);
	u32 comparator = readl(wdt->reg + WDT_COMPARATOR);
	u32 count = readl(wdt->reg + WDT_COUNT);

	return (comparator - count) / wdt->rate;
}

static int apple_wdt_restart(struct watchdog_device *w, unsigned long mode,
			     void *cmd)
{
	struct apple_wdt *wdt = watchdog_get_drvdata(w);

	writel(0, wdt->reg + WDT_COUNT);
	writel(U32_MAX, wdt->reg + WDT_COMPARATOR);
	writel(WDT_CONTROL_TRIGGER, wdt->reg + WDT_CONTROL);
	writel(0, wdt->reg + WDT_COMPARATOR);

	return 0;
}

static struct watchdog_ops apple_wdt_ops = {
	.start = apple_wdt_start,
	.stop = apple_wdt_stop,
	.ping = apple_wdt_ping,
	.set_timeout = apple_wdt_set_timeout,
	.get_timeleft = apple_wdt_get_timeleft,
	.restart = apple_wdt_restart,
};

static struct watchdog_info apple_wdt_info = {
	.identity = "Apple WDT",
	.options = WDIOF_SETTIMEOUT,
};

static int apple_wdt_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct apple_wdt *wdt = devm_kzalloc(dev, sizeof(*wdt), GFP_KERNEL);
	struct watchdog_device *wd = devm_kzalloc(dev, sizeof(*wd), GFP_KERNEL);
	int ret;

	if (!wdt || !wd)
		return -ENOMEM;

	wdt->clk = devm_clk_get(dev, NULL);
	if (IS_ERR(wdt->clk))
		return PTR_ERR(wdt->clk);

	wd->ops = &apple_wdt_ops;
	wd->info = &apple_wdt_info;

	wdt->reg = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(wdt->reg))
		return PTR_ERR(wdt->reg);

	ret = clk_prepare_enable(wdt->clk);
	if (ret)
		return ret;

	wdt->rate = clk_get_rate(wdt->clk);

	if (readl(wdt->reg + WDT_CONTROL) & WDT_CONTROL_TRIGGER)
		wd->status |= WDOG_HW_RUNNING;

	ret = devm_watchdog_register_device(dev, wd);
	if (ret < 0) {
		clk_disable_unprepare(wdt->clk);
		return ret;
	}

	watchdog_set_drvdata(wd, wdt);
	platform_set_drvdata(pdev, wd);

	return 0;
}

static int apple_wdt_remove(struct platform_device *pdev)
{
	struct watchdog_device *wd = platform_get_drvdata(pdev);
	struct apple_wdt *wdt = watchdog_get_drvdata(wd);

	clk_disable_unprepare(wdt->clk);

	return 0;
}

static const struct of_device_id apple_wdt_of_match[] = {
	{ .compatible = "apple,t8103-wdt" },
	{ },
};

MODULE_DEVICE_TABLE(of, apple_wdt_of_match);

static struct platform_driver apple_wdt_driver = {
	.driver = {
		.name = "apple-wdt",
		.of_match_table = of_match_ptr(apple_wdt_of_match),
	},
	.probe = apple_wdt_probe,
	.remove = apple_wdt_remove,
};
module_platform_driver(apple_wdt_driver);

MODULE_AUTHOR("Pip Cet <pipcet@gmail.com>");
MODULE_DESCRIPTION("Watchdog Timer driver for Apple M1");
MODULE_LICENSE("Dual MIT/GPL");
