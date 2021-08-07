// SPDX-License-Identifier: GPL-2.0+
/*
 * GPIO pins implemented via key-value boxes.
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
	size_t suffix_len;
	const u8 *suffix;
	const u8 *write_enable;
	size_t write_enable_len;
	const u8 *write_disable;
	size_t write_disable_len;
	struct mutex mutex;
	struct completion c;
};

static void gpio_kvbox_callback(void *ptr)
{
	struct completion *c = ptr;
	complete_all(c);
}

static int gpio_kvbox_get(struct gpio_chip *chip, unsigned int offset)
{
	struct gpio_kvbox *gpio = container_of(chip, struct gpio_kvbox, gpio);
	u8 *key;
	size_t len;
	int ret;
	struct kvbox_prop prop;

	mutex_lock(&gpio->mutex);
	prop.data = devm_kzalloc(gpio->dev, gpio->write_disable_len, GFP_KERNEL);
	prop.data_len = gpio->write_disable_len;

	if (!prop.data)
		return -ENOMEM;

	len = strlen(gpio->keys[offset]);
	key = devm_kzalloc(gpio->dev, len + gpio->suffix_len, GFP_KERNEL);

	if (!key) {
		mutex_unlock(&gpio->mutex);
		devm_kfree(gpio->dev, prop.data);
		return -ENOMEM;
	}

	prop.key = key;
	prop.key_len = len + gpio->suffix_len;

	memcpy(key, gpio->keys[offset], len);
	memcpy(key + len, gpio->suffix, gpio->suffix_len);

	reinit_completion(&gpio->c);
	ret = kvbox_read(gpio->kvbox, &prop, gpio_kvbox_callback, &gpio->c);
	if (ret >= 0)
		wait_for_completion(&gpio->c);

	devm_kfree(gpio->dev, key);
	if (ret >= 0)
		ret = memcmp(prop.data, gpio->write_disable, gpio->write_disable_len);
	devm_kfree(gpio->dev, prop.data);
	mutex_unlock(&gpio->mutex);

	return ret;
}


static int gpio_kvbox_direction_output(struct gpio_chip *chip, unsigned int offset, int value)
{
	struct gpio_kvbox *gpio = container_of(chip, struct gpio_kvbox, gpio);
	struct kvbox_prop prop;
	u32 data = value ? 1 : 0;
	int ret;

	do {
		mutex_lock(&gpio->mutex);
		prop.key = gpio->keys[offset];
		prop.key_len = strlen(prop.key);
		prop.data = value ? gpio->write_enable : gpio->write_disable;
		prop.data_len = value ? gpio->write_enable_len : gpio->write_disable_len;

		reinit_completion(&gpio->c);
		ret = kvbox_write(gpio->kvbox, &prop, gpio_kvbox_callback, &gpio->c);
		if (ret >= 0)
			wait_for_completion(&gpio->c);
		mutex_unlock(&gpio->mutex);
	} while (ret < 0);

	return ret < 0 ? ret : 0;
}

static void gpio_kvbox_set(struct gpio_chip *chip, unsigned int offset,
			   int value)
{
	gpio_kvbox_direction_output(chip, offset, value);
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
	gpio->gpio.label = "gpio-kvbox";
	of_property_read_string(gpio->dev->of_node, "gpio-name",
			       &gpio->gpio.label);

	gpio->gpio.owner = THIS_MODULE;
	gpio->gpio.set = gpio_kvbox_set;
	gpio->gpio.get = gpio_kvbox_get;
	gpio->gpio.direction_output = gpio_kvbox_direction_output;
	gpio->gpio.base = -1;
	gpio->gpio.parent = gpio->dev;
	gpio->gpio.can_sleep = true;

	count = of_property_count_strings(gpio->dev->of_node,
					  "kvbox-keys");
	gpio->gpio.ngpio = count;

	gpio->keys = devm_kcalloc(gpio->dev, count, sizeof gpio->keys[0],
				  GFP_KERNEL);

	gpio->suffix_len = of_property_count_u8_elems
		(gpio->dev->of_node, "kvbox-read-suffix");

	if (gpio->suffix_len <= 0)
		gpio->suffix_len = 0;
	else {
		u8 * suffix;
		suffix = devm_kzalloc(gpio->dev,
					    gpio->suffix_len, GFP_KERNEL);
		if (!suffix)
			return -ENOMEM;
		of_property_read_u8_array(gpio->dev->of_node, "kvbox-read-suffix",
					  suffix, gpio->suffix_len);
		gpio->suffix = suffix;
	}

	gpio->write_enable_len = of_property_count_u8_elems
		(gpio->dev->of_node, "kvbox-write-enable");

	if (gpio->write_enable_len <= 0)
		gpio->write_enable_len = 0;
	else {
		u8 * write_enable;
		write_enable = devm_kzalloc(gpio->dev,
					    gpio->write_enable_len, GFP_KERNEL);
		if (!write_enable)
			return -ENOMEM;
		of_property_read_u8_array(gpio->dev->of_node, "kvbox-write-enable",
					  write_enable, gpio->write_enable_len);
		gpio->write_enable = write_enable;
	}

	gpio->write_disable_len = of_property_count_u8_elems
		(gpio->dev->of_node, "kvbox-write-disable");

	if (gpio->write_disable_len <= 0)
		gpio->write_disable_len = 0;
	else {
		u8 * write_disable;
		write_disable = devm_kzalloc(gpio->dev,
					    gpio->write_disable_len, GFP_KERNEL);
		if (!write_disable)
			return -ENOMEM;
		of_property_read_u8_array(gpio->dev->of_node, "kvbox-write-disable",
					  write_disable, gpio->write_disable_len);
		gpio->write_disable = write_disable;
	}

	if (!gpio->keys)
		return -ENOMEM;

	if (of_property_read_string_array(gpio->dev->of_node, "kvbox-keys",
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
