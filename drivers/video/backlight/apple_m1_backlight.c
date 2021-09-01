#include <linux/apple-asc.h>
#include <linux/backlight.h>
#include <linux/kvbox.h>
#include <linux/mailbox_client.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>

#define TIMEOUT_MSEC 800

struct apple_backlight {
	struct device *dev;
	struct backlight_device *backlight_device;
	struct kvbox *kvbox;
	struct kvbox_prop prop;
	u32 brightness;
	u64 max_brightness;
};

static const struct of_device_id apple_backlight_of_match[] = {
	{ .compatible = "apple,apple-m1-backlight" },
	{ },
};

static int apple_backlight_update_status(struct backlight_device *bld)
{
	struct apple_backlight *backlight = bl_get_data(bld);
	int ret;

	backlight->brightness = backlight_get_brightness(bld);
	backlight->prop.key = "0000000f"
	backlight->prop.key_len = 8;
	backlight->prop.data = &backlight->brightness;
	backlight->prop.data_len = sizeof(backlight->brightness);
	ret = kvbox_write(backlight->kvbox, &backlight->prop,
			  NULL, NULL);

	if (ret < 0)
		return ret;

	return 0;
}

static struct backlight_ops apple_backlight_ops = {
	.update_status = apple_backlight_update_status,
};

static int apple_backlight_probe(struct platform_device *pdev)
{
	struct apple_backlight *backlight;
	struct backlight_properties props;

	backlight = devm_kzalloc(&pdev->dev, sizeof *backlight, GFP_KERNEL);
	if (!backlight)
		return -ENOMEM;

	backlight->dev = &pdev->dev;
	backlight->max_brightness = 0x20d0000;
	of_property_read_u64(pdev->dev.of_node, "max-brightness",
			     &backlight->max_brightness);

	backlight->kvbox = kvbox_request(&pdev->dev, 0);
	if (IS_ERR(backlight->kvbox)) {
		dev_err(backlight->dev, "couldn't acquire kvbox");
		return PTR_ERR(backlight->kvbox);
	}

	props.max_brightness = backlight->max_brightness;
	props.type = BACKLIGHT_FIRMWARE;
	/* experimentally, power consumption is linear, so brightness
	 * probably is, too. */
	props.scale = BACKLIGHT_SCALE_LINEAR;
	props.brightness = props.max_brightness;
	props.power = FB_BLANK_UNBLANK;
	props.fb_blank = FB_BLANK_UNBLANK;

	backlight->backlight_device = devm_backlight_device_register
		(backlight->dev, "apple_m1_backlight", NULL, backlight,
		 &apple_backlight_ops, &props);

	if (IS_ERR(backlight->backlight_device))
		return PTR_ERR(backlight->backlight_device);

	return 0;
}

static struct platform_driver apple_backlight_platform_driver = {
	.driver = {
		.name = "apple-m1-backlight",
		.of_match_table = apple_backlight_of_match,
	},
	.probe = apple_backlight_probe,
};

module_platform_driver(apple_backlight_platform_driver);
MODULE_AUTHOR("Pip Cet <pipcet@gmail.com>");
MODULE_DESCRIPTION("Backlight driver for M1-based laptops");
MODULE_LICENSE("GPL");
