// SPDX-License-Identifier: GPL-2.0-only
/*
 * Driver for Apple M1 FPWM.  Used for the keyboard backlight on at
 * least some MacBook Pros.
 *
 * Copyright (C) 2021 Pip Cet <pipcet@gmail.com>
 *
 * Based on pwm-twl-led.c, which is:
 *
 * Copyright (C) 2012 Texas Instruments
 * Author: Peter Ujfalusi <peter.ujfalusi@ti.com>
 */

#include <linux/clk.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/pwm.h>
#include <linux/slab.h>

#define FPWM_CONTROL           0x00
#define FPWM_CONTROL_UPDATE  0x4239
#define FPWM_CONTROL_DISABLE      0
#define FPWM_STATUS            0x08
#define FPWM_COUNT_OFF         0x18
#define FPWM_COUNT_ON          0x1c
#define FPWM_HZ   (24 * 1000 * 1000)

struct fpwm_chip {
	struct pwm_chip chip;
	void __iomem *regbase;
	struct clk *clk;
	struct mutex mutex; // XXX
};

static inline struct fpwm_chip *to_fpwm(struct pwm_chip *chip)
{
	return container_of(chip, struct fpwm_chip, chip);
}

static int fpwm_config(struct pwm_chip *chip, struct pwm_device *pwm,
		       int duty_ns, int period_ns)
{
	struct fpwm_chip *fpwm = to_fpwm(chip);
	long duty_ticks = duty_ns * 3L / (1000000000L * 3 / FPWM_HZ);
	long period_ticks = period_ns * 3L / (1000000000L * 3 / FPWM_HZ);
	long off_ticks = period_ticks - duty_ticks;

	writel(duty_ticks, fpwm->regbase + FPWM_COUNT_ON);
	writel(off_ticks, fpwm->regbase + FPWM_COUNT_OFF);
	writel(FPWM_CONTROL_UPDATE, fpwm->regbase + FPWM_CONTROL);

	return 0;
}

static int fpwm_enable(struct pwm_chip *chip, struct pwm_device *pwm)
{
	struct fpwm_chip *fpwm = to_fpwm(chip);

	writel(FPWM_CONTROL_UPDATE, fpwm->regbase + FPWM_CONTROL);

	return 0;
}

static void fpwm_disable(struct pwm_chip *chip, struct pwm_device *pwm)
{
	struct fpwm_chip *fpwm = to_fpwm(chip);

	writel(FPWM_CONTROL_DISABLE, fpwm->regbase + FPWM_CONTROL);
}

static const struct pwm_ops fpwm_ops = {
	.enable = fpwm_enable,
	.disable = fpwm_disable,
	.config = fpwm_config,
	.owner = THIS_MODULE,
};

static int fpwm_probe(struct platform_device *pdev)
{
	struct fpwm_chip *fpwm;
	struct resource *rsrc;
	int ret;

	fpwm = devm_kzalloc(&pdev->dev, sizeof(*fpwm), GFP_KERNEL);
	if (!fpwm)
		return -ENOMEM;

	fpwm->chip.ops = &fpwm_ops;
	fpwm->chip.npwm = 1;
	fpwm->chip.dev = &pdev->dev;
	fpwm->chip.base = -1;

	mutex_init(&fpwm->mutex);

	ret = pwmchip_add(&fpwm->chip);
	if(ret < 0)
		return ret;

	platform_set_drvdata(pdev, fpwm);

	rsrc = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	fpwm->regbase = devm_ioremap_resource(&pdev->dev, rsrc);
	if(IS_ERR(fpwm->regbase))
		return PTR_ERR(fpwm->regbase);

	fpwm->clk = devm_clk_get(&pdev->dev, NULL);
	if(IS_ERR(fpwm->clk)) {
		dev_err(&pdev->dev, "unable to get clock: %ld\n",
		        PTR_ERR(fpwm->clk));
		return PTR_ERR(fpwm->clk);
	}

	ret = clk_prepare_enable(fpwm->clk);
	if(ret)
		return ret;

	return 0;
}

static int fpwm_remove(struct platform_device *pdev)
{
	struct fpwm_chip *fpwm = platform_get_drvdata(pdev);

	int ret = pwmchip_remove(&fpwm->chip);

	if (ret < 0)
	  return ret;

	clk_disable_unprepare(fpwm->clk);

	return 0;
}

#ifdef CONFIG_OF
static const struct of_device_id fpwm_of_match[] = {
	{ .compatible = "apple,fpwm-t8101" },
	{ .compatible = "apple,fpwm-s5l8920x" },
	{ },
};
MODULE_DEVICE_TABLE(of, fpwm_of_match);
#endif

static struct platform_driver fpwm_driver = {
	.driver = {
		.name = "apple-m1-fpwm",
		.of_match_table = of_match_ptr(fpwm_of_match),
	},
	.probe = fpwm_probe,
	.remove = fpwm_remove,
};
module_platform_driver(fpwm_driver);

MODULE_AUTHOR("Pip Cet <pipcet@gmail.com>");
MODULE_DESCRIPTION("PWM driver for Apple M1 FPWM");
MODULE_ALIAS("platform:apple-m1-fpwm");
MODULE_LICENSE("GPL");
