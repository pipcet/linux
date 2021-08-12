// SPDX-License-Identifier: GPL-2.0+
/*
 * General driver for exposing kvbox properties as GPIO pins.
 *
 * Copyright (C) 2021 Pip Cet <pipcet@gmail.com>
 */

#include <linux/of_device.h>
#include <linux/module.h>
#include <linux/gpio/driver.h>
#include "kvbox.h"

struct gpio_kvbox {
	struct device *dev;
	struct kvbox *kvbox;
	struct gpio_chip gpio;
	const char **keys;
	struct mutex mutex;
	struct completion c;
};

static void gpio_kvbox_callback(void *ptr)
{
	struct completion *c = ptr;
	complete_all(c);
}

static void gpio_kvbox_set(struct gpio_chip *chip, unsigned int offset,
			   int value)
{
	struct gpio_kvbox *gpio = container_of(chip, struct gpio_kvbox, gpio);
	struct kvbox_prop prop;
	u32 data = value ? 1 : 0;
	int ret;
	prop.key = gpio->keys[offset];
	prop.key_len = strlen(prop.key);
	prop.data = &data;
	prop.data_len = sizeof data;

	mutex_lock(&gpio->mutex);
	reinit_completion(&gpio->c);
	ret = kvbox_write(gpio->kvbox, &prop, gpio_kvbox_callback, &gpio->c);
	if (ret >= 0)
		wait_for_completion(&gpio->c);
	mutex_unlock(&gpio->mutex);
}

static int gpio_kvbox_probe(struct platform_device *pdev)
{
	struct gpio_kvbox *gpio = devm_kzalloc(&pdev->dev, sizeof *gpio,
					       GFP_KERNEL);
	int ret;
	unsigned count;

	if (!gpio)
		return -ENOMEM;

	gpio->dev = &pdev->dev;

	init_completion(&gpio->c);
	mutex_init(&gpio->mutex);
	gpio->gpio.label = "smc-gP";
	gpio->gpio.owner = THIS_MODULE;
	gpio->gpio.set = gpio_kvbox_set;
	gpio->gpio.base = -1;

	count = of_property_count_strings(gpio->dev->of_node,
					  "gpio-line-names");
	gpio->gpio.ngpio = count;

	gpio->keys = devm_kcalloc(gpio->dev, count, sizeof gpio->keys[0],
				  GFP_KERNEL);

	if (!gpio->keys)
		return -ENOMEM;

	if (of_property_read_string_array(gpio->dev->of_node, "gpio-line-names",
					  gpio->keys, count) != count)
		return -EINVAL;

	gpio->kvbox = kvbox_request(&pdev->dev, 0);

	if (IS_ERR(gpio->kvbox))
		return PTR_ERR(gpio->kvbox);

	ret = devm_gpiochip_add_data(gpio->dev, &gpio->gpio, gpio);

	if (ret < 0)
		return ret;

	return 0;
}

static const struct of_device_id gpio_kvbox_of_match[] = {
	{ .compatible = "kvbox-gpio" },
	{ },
};
MODULE_DEVICE_TABLE(of, gpio_kvbox_of_match);

static struct platform_driver gpio_kvbox_platform_driver = {
	.driver = {
		.name = "gpio-kvbox",
		.of_match_table = gpio_kvbox_of_match,
	},
	.probe = gpio_kvbox_probe,
};
module_platform_driver(gpio_kvbox_platform_driver);

MODULE_LICENSE("GPL");
