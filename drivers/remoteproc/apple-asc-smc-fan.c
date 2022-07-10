#include <linux/hwmon.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/leds.h>
#include <linux/kvbox.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/thermal.h>

static int float_to_int(void *ptr)
{
	u32 f = *(u32 *)ptr;
	u32 exp = f >> 23;
	u32 mantissa = f & ((1<<23) - 1);
	if (f == 0)
		return 0;
	mantissa += (1<<23);
	return mantissa >> (17 + (0x85 - exp));
}

struct smc_fan {
	struct device *dev;
	struct thermal_cooling_device *cdev;
	struct kvbox *kvbox;
	struct kvbox_prop prop;
	struct device *hwmon;
	struct hwmon_chip_info info;
	struct hwmon_channel_info fan_channel;
	int manual_mode;
	u32 max_speed;
	u32 min_speed;
};

static int smc_fan_get_max_state(struct thermal_cooling_device *cdev, unsigned long *rate)
{
	struct smc_fan *fan = cdev->devdata;
	struct kvbox_prop prop;
	int ret;
	u32 rate_f;

	prop.key = "F0Mx";
	prop.key_len = 4;
	prop.data = &rate_f;
	prop.data_len = 4;

	ret = kvbox_read_interruptible(fan->kvbox, &prop);
	if (ret < 0)
		return ret;

	*rate = (float_to_int(prop.data) + 99) / 100;

	return 0;
}

static int smc_fan_set_cur_state(struct thermal_cooling_device *cdev, unsigned long rate)
{
	struct smc_fan *fan = cdev->devdata;
	struct kvbox_prop prop;
	int ret;
	u32 rate_f;
	int rate_e = 0;
	u32 rate_m = rate * 100;

	if (!fan->manual_mode) {
		u8 c = 1;
		prop.key = "F0Md";
		prop.key_len = 4;
		prop.data = &c;
		prop.data_len = 1;

		ret = kvbox_write_interruptible(fan->kvbox, &prop);
		if (ret < 0)
			return ret;

		fan->manual_mode = 1;
	}

	if (rate == 0)
		rate_f = 0;
	else {
		rate_e = 0x85 + 17;
		while (!(rate_m & (1 << 23))) {
			rate_m <<= 1;
			rate_e--;
		}
		rate_f = (rate_e << 23);
		rate_m &= ~(1 << 23);
		rate_f |= rate_m;
	}

	prop.key = "F0Tg";
	prop.key_len = 4;
	prop.data = &rate_f;
	prop.data_len = 4;

	ret = kvbox_write_interruptible(fan->kvbox, &prop);
	if (ret < 0)
		return ret;

	return 0;
}

static int smc_fan_get_cur_state(struct thermal_cooling_device *cdev, unsigned long *rate)
{
	struct smc_fan *fan = cdev->devdata;
	struct kvbox_prop prop;
	int ret;
	u32 rate_f;

	prop.key = "F0Tg";
	prop.key_len = 4;
	prop.data = &rate_f;
	prop.data_len = 4;

	ret = kvbox_read_interruptible(fan->kvbox, &prop);
	if (ret < 0)
		return ret;

	*rate = (float_to_int(prop.data) + 99) / 100;

	return 0;
}

static struct thermal_cooling_device_ops smc_fan_cooling_ops = {
	.get_max_state = smc_fan_get_max_state,
	.get_cur_state = smc_fan_get_cur_state,
	.set_cur_state = smc_fan_set_cur_state,
};

static int smc_fan_of_get_cooling_data(struct device *dev,
				       struct smc_fan *fan)
{
	return 0;
}

static int smc_fan_probe(struct platform_device *pdev)
{
	struct smc_fan *fan;

	fan = devm_kzalloc(&pdev->dev, sizeof *fan, GFP_KERNEL);
	if (!fan)
		return -ENOMEM;
	fan->dev = &pdev->dev;
	fan->max_speed = 0xffff;
	fan->min_speed = 0xffff;
	fan->kvbox = kvbox_request(&pdev->dev, 0);
	if (IS_ERR(fan->kvbox)) {
		dev_err(fan->dev, "couldn't acquire kvbox");
		return PTR_ERR(fan->kvbox);
	}

	fan->fan_channel.type = hwmon_fan;

#if 0
	fan->hwmon = devm_hwmon_device_register_with_info(&pdev->dev, "apple-asc-smc-fan",
							  fan, &fan->info, NULL);

	if (IS_ERR(fan->hwmon))
		return PTR_ERR(fan->hwmon);
#endif

	fan->cdev =
		devm_thermal_of_cooling_device_register(&pdev->dev,
							pdev->dev.of_node,
							"smc-fan",
							fan,
							&smc_fan_cooling_ops);

	if (IS_ERR(fan->cdev))
		return PTR_ERR(fan->cdev);

	return 0;
}

static const struct of_device_id smc_fan_of_match[] = {
	{ .compatible = "apple,apple-asc-smc-fan" },
	{ },
};

MODULE_DEVICE_TABLE(of, smc_fan_of_match);

static struct platform_driver smc_fan_driver = {
	.probe = smc_fan_probe,
	.driver = {
		.name = "apple-asc-smc-fan",
		.of_match_table = smc_fan_of_match,
	},
};

module_platform_driver(smc_fan_driver);

MODULE_LICENSE("GPL");
