#include <linux/apple-asc.h>
#include <linux/backlight.h>
#include <linux/gpio/consumer.h>
#include <linux/kvbox.h>
#include <linux/mailbox_client.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>

#define TIMEOUT_MSEC 800

struct apple_hdmi {
	struct device *dev;
	struct backlight_device *backlight_device;
	struct apple_dcp *dcp;
	u32 brightness;
	u64 max_brightness;
};

static const struct of_device_id apple_hdmi_of_match[] = {
	{ .compatible = "apple,apple-dcp-hdmi" },
	{ },
};

extern void apple_dcp_set_power(struct apple_dcp *, int state);
static int apple_hdmi_update_status(struct backlight_device *bld)
{
	struct apple_hdmi *hdmi = bl_get_data(bld);
	int ret;

	hdmi->brightness = backlight_get_brightness(bld);
	apple_dcp_set_power(hdmi->dcp, hdmi->brightness != 0);

	return 0;
}

static struct backlight_ops apple_hdmi_ops = {
	.update_status = apple_hdmi_update_status,
};

static int apple_hdmi_probe(struct platform_device *pdev)
{
	struct apple_hdmi *hdmi;
	struct backlight_properties props;
	int ret = 0;

	hdmi = devm_kzalloc(&pdev->dev, sizeof *hdmi, GFP_KERNEL);
	if (!hdmi)
		return -ENOMEM;

	hdmi->dev = &pdev->dev;
	hdmi->max_brightness = 0x20d0000;
	of_property_read_u64(pdev->dev.of_node, "max-brightness",
			     &hdmi->max_brightness);

	props.max_brightness = hdmi->max_brightness;
	props.type = BACKLIGHT_FIRMWARE;
	/* experimentally, power consumption is linear, so brightness
	 * probably is, too. */
	props.scale = BACKLIGHT_SCALE_LINEAR;
	props.brightness = props.max_brightness;
	props.power = FB_BLANK_UNBLANK;
	props.fb_blank = FB_BLANK_UNBLANK;

	hdmi->backlight_device = devm_backlight_device_register
		(hdmi->dev, "apple_dcp_hdmi", hdmi->dev, hdmi,
		 &apple_hdmi_ops, &props);

	if (IS_ERR(hdmi->backlight_device))
		return PTR_ERR(hdmi->backlight_device);

	return 0;
}

static struct platform_driver apple_hdmi_platform_driver = {
	.driver = {
		.name = "apple-dcp-hdmi",
		.of_match_table = apple_hdmi_of_match,
	},
	.probe = apple_hdmi_probe,
};

module_platform_driver(apple_hdmi_platform_driver);
MODULE_AUTHOR("Pip Cet <pipcet@gmail.com>");
MODULE_DESCRIPTION("HDMI driver for M1-based laptops");
MODULE_LICENSE("GPL");
