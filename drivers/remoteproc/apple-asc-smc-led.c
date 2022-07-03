#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/leds.h>
#include <linux/kvbox.h>
#include <linux/platform_device.h>
#include <linux/of.h>

struct apple_smc_led {
	struct device *dev;
	struct led_classdev led;
	struct kvbox *kvbox;
	struct kvbox_prop prop;
	u32 max_brightness;
};

static const struct of_device_id apple_asc_smc_led_of_match[] = {
	{ .compatible = "apple,apple-asc-smc-led" },
	{ },
};

static void apple_asc_smc_led_brightness_set(struct led_classdev *led_classdev,
					     enum led_brightness value)
{
	struct apple_smc_led *led =
		container_of(led_classdev, struct apple_smc_led, led);
	int ret;
	u16 raw_value = value * (u64)led->max_brightness / 255;
	led->prop.key = "LS0S";
	led->prop.key_len = 4;
	led->prop.data = &raw_value;
	led->prop.data_len = 2;
	ret = kvbox_write(led->kvbox, &led->prop, NULL, NULL);
	if (ret < 0)
		dev_err(led->dev, "couldn't set brightness");
}

static int apple_asc_smc_led_probe(struct platform_device *pdev)
{
	struct apple_smc_led *led;
	int ret;

	led = devm_kzalloc(&pdev->dev, sizeof *led, GFP_KERNEL);
	if (!led)
		return -ENOMEM;
	led->dev = &pdev->dev;
	led->max_brightness = 0xffff;
	led->kvbox = kvbox_request(&pdev->dev, 0);
	if (IS_ERR(led->kvbox)) {
		dev_err(led->dev, "couldn't acquire kvbox");
		return PTR_ERR(led->kvbox);
	}

	led->led.name = "power";
	led->led.default_trigger = "heartbeat";
	led->led.brightness_set = apple_asc_smc_led_brightness_set;

	ret = devm_led_classdev_register(led->dev, &led->led);
	if (ret)
		return ret;

	return 0;
}

static struct platform_driver smc_led_driver = {
	.probe = apple_asc_smc_led_probe,
	.driver = {
		.name = "smc-led",
		.of_match_table = apple_asc_smc_led_of_match,
	},
};

module_platform_driver(smc_led_driver);

MODULE_LICENSE("GPL");
