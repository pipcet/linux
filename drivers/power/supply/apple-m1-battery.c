// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 Pip Cet <pipcet@gmail.com>
 */

#include <linux/device.h>
#include <linux/kvbox.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/power_supply.h>

static const enum power_supply_property properties[] = {
	POWER_SUPPLY_PROP_CAPACITY,
	POWER_SUPPLY_PROP_ENERGY_NOW,
	POWER_SUPPLY_PROP_ENERGY_FULL,
};

struct apple_battery {
	struct device *dev;
	struct power_supply *psy;
	struct kvbox *kvbox;
	struct kvbox_prop sbas;
	u32 key_capacity;
	u32 key_energy_now;
	u32 key_energy_full;
};

static int float_to_percentage(void *ptr)
{
	u32 f = *(u32 *)ptr;
	u32 exp = f >> 23;
	u32 mantissa = f & ((1<<23) - 1);
	mantissa += (1<<23);
	return mantissa >> (17 + (0x85 - exp));
}

static int apple_battery_get_property(struct power_supply *psy,
				      enum power_supply_property psp,
				      union power_supply_propval *val)
{
	struct apple_battery *batt = power_supply_get_drvdata(psy);
	switch (psp) {
	case POWER_SUPPLY_PROP_ENERGY_FULL:
		val->intval = 100;
		return 0;
	case POWER_SUPPLY_PROP_ENERGY_NOW:
	case POWER_SUPPLY_PROP_CAPACITY:
		kvbox_read_interruptible(batt->kvbox, &batt->sbas);
		val->intval = float_to_percentage(batt->sbas.data);
		return 0;
	default:
		return -EINVAL;
	}
}

static int apple_battery_property_is_writable(struct power_supply *psy,
					      enum power_supply_property psp)
{
	return 0;
}

static const struct power_supply_desc desc = {
	.name = "smc_battery",
	.type = POWER_SUPPLY_TYPE_BATTERY,
	.properties = properties,
	.num_properties = ARRAY_SIZE(properties),
	.get_property = apple_battery_get_property,
	.property_is_writeable = apple_battery_property_is_writable,
	.use_for_apm = 1,
};

static int apple_battery_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct power_supply_config *cfg =
	       devm_kzalloc(dev, sizeof(*cfg), GFP_KERNEL);
	struct apple_battery *batt =
	       devm_kzalloc(dev, sizeof(*batt), GFP_KERNEL);
	void *key;

	if (cfg == NULL)
		return -ENOMEM;

	if (batt == NULL)
		return -ENOMEM;

	cfg->of_node = dev->of_node;
	cfg->fwnode = dev->fwnode;
	cfg->drv_data = batt;
	batt->dev = dev;
	batt->sbas.key = key = devm_kzalloc(dev, 4, GFP_KERNEL);
	batt->sbas.data = devm_kzalloc(dev, 4, GFP_KERNEL);
	if (!batt->sbas.key || !batt->sbas.data)
		return -ENOMEM;
	memcpy(key, "SBAS", 4);
	batt->sbas.key_len = 4;
	batt->sbas.data_len = 4;

	batt->kvbox = kvbox_request(dev, 0);
	if (IS_ERR(batt->kvbox))
		return PTR_ERR(batt->kvbox);

	batt->psy = devm_power_supply_register(dev, &desc, cfg);
	if (IS_ERR(batt->psy))
		return PTR_ERR(batt->psy);

	return 0;
}

static const struct of_device_id apple_battery_of_match[] = {
	{ .compatible = "kvbox-battery" },
	{ },
};

MODULE_DEVICE_TABLE(of, apple_battery_of_match);

static struct platform_driver apple_battery_driver = {
	.driver = {
		.name = "apple-m1-battery",
		.of_match_table = of_match_ptr(apple_battery_of_match),
	},
	.probe = apple_battery_probe,
};
module_platform_driver(apple_battery_driver);

MODULE_AUTHOR("Pip Cet <pipcet@gmail.com>");
MODULE_DESCRIPTION("Battery status driver for Apple M1");
MODULE_ALIAS("platform:apple-m1-battery");
MODULE_LICENSE("GPL");
