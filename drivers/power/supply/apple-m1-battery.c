// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 Pip Cet <pipcet@gmail.com>
 */

#include <linux/module.h>
#include <linux/device.h>
#include <linux/power_supply.h>
#include <linux/platform_device.h>
#include <linux/of.h>

static const enum power_supply_property properties[] = {
	POWER_SUPPLY_PROP_CAPACITY,
	POWER_SUPPLY_PROP_ENERGY_NOW,
	POWER_SUPPLY_PROP_ENERGY_FULL,
};

extern int apple_m1_smc_read_percentage(struct device *dev, u32 key,
					int *pval);

extern int apple_m1_smc_read_ui16(struct device *dev, u32 key,
				  int *pval);

extern int apple_m1_smc_read_float(struct device *dev, u32 key,
				   int *pval);

struct apple_battery {
	struct platform_device *pdev;
	struct power_supply *psy;
	u32 key_capacity;
	u32 key_energy_now;
	u32 key_energy_full;
};

static int apple_battery_get_property(struct power_supply *psy,
				      enum power_supply_property psp,
				      union power_supply_propval *val)
{
	struct apple_battery *batt = power_supply_get_drvdata(psy);
	u32 key;
	switch (psp) {
	case POWER_SUPPLY_PROP_CAPACITY:
		key = batt->key_capacity;
		apple_m1_smc_read_percentage(&batt->pdev->dev, key,
					     &val->intval);
		return 0;
	case POWER_SUPPLY_PROP_ENERGY_NOW:
		key = batt->key_energy_now;
		apple_m1_smc_read_float(&batt->pdev->dev, key,
				       &val->intval);
		return 0;
	case POWER_SUPPLY_PROP_ENERGY_FULL:
		key = batt->key_energy_full;
		apple_m1_smc_read_ui16(&batt->pdev->dev, key,
				       &val->intval);
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
	       devm_kzalloc(dev, sizeof *cfg, GFP_KERNEL);
	struct apple_battery *batt =
	       devm_kzalloc(dev, sizeof *batt, GFP_KERNEL);

	if (cfg == NULL)
		return -ENOMEM;

	if (batt == NULL)
		return -ENOMEM;

	cfg->of_node = pdev->dev.of_node;
	cfg->fwnode = pdev->dev.fwnode;
	cfg->drv_data = batt;
	batt->pdev = pdev;
	batt->psy = devm_power_supply_register(dev, &desc, cfg);

	of_property_read_u32_index(dev->of_node, "reg", 0,
				   &batt->key_capacity);

	of_property_read_u32_index(dev->of_node, "reg", 2,
				   &batt->key_energy_now);

	of_property_read_u32_index(dev->of_node, "reg", 4,
				   &batt->key_energy_full);

	if (IS_ERR(batt->psy))
		return PTR_ERR(batt->psy);

	return 0;
}

static int apple_battery_remove(struct platform_device *pdev)
{
	struct apple_battery *batt = platform_get_drvdata(pdev);
	power_supply_unregister(batt->psy);

	return 0;
}

static const struct of_device_id apple_battery_of_match[] = {
	{ .compatible = "apple,battery" },
	{ },
};

MODULE_DEVICE_TABLE(of, apple_battery_of_match);

static struct platform_driver apple_battery_driver = {
	.driver = {
		.name = "apple-m1-battery",
		.of_match_table = of_match_ptr(apple_battery_of_match),
	},
	.probe = apple_battery_probe,
	.remove = apple_battery_remove,
};
module_platform_driver(apple_battery_driver);

MODULE_AUTHOR("Pip Cet <pipcet@gmail.com>");
MODULE_DESCRIPTION("Battery status driver for Apple M1");
MODULE_ALIAS("platform:apple-m1-battery");
MODULE_LICENSE("GPL");
