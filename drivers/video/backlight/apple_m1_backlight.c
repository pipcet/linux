#include <linux/backlight.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/mailbox_client.h>

#define TIMEOUT_MSEC 800

struct apple_mbox_msg {
	u64 payload;
	u64 endpoint;
};

struct apple_dcp_msg_header {
	u32 code;
	u32 len_input;
	u32 len_output;
};

struct apple_dcp_mbox_msg {
	struct apple_mbox_msg mbox;
	struct apple_dcp_msg_header dcp;
	char dcp_data[];
};

struct apple_backlight {
	struct device *dev;
	struct backlight_device *backlight_device;
	struct mbox_client cl;
	struct mbox_chan *chan;
	u64 max_brightness;
};

static const struct of_device_id apple_backlight_of_match[] = {
	{ .compatible = "apple,apple-m1-backlight" },
	{ },
};

static int apple_backlight_update_status(struct backlight_device *bld)
{
	struct apple_backlight *backlight = bl_get_data(bld);
	struct apple_dcp_mbox_msg *msg = kzalloc(sizeof(*msg) + 0x100,
						 GFP_KERNEL);
	int ret;
	u32 payload[] = { 15, backlight_get_brightness(bld), 0 };
	/* message type 2, command context */
	msg->mbox.payload = 0x0202;
	msg->mbox.endpoint = 0x37;
	/* entry point A352 */
	msg->dcp.code = 0x41333532;
	msg->dcp.len_input = 8;
	msg->dcp.len_output = 4;
	memcpy(msg->dcp_data, payload, sizeof(payload));

	printk("sending msg\n");
	ret = mbox_send_message(backlight->chan, msg);
	kfree(msg);

	if (ret < 0)
		return ret;

	return 0;
}

static void apple_backlight_receive_data(struct mbox_client *cl, void *msg)
{
	/* That's very interesting. Tell me more. */
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

	backlight->cl.dev = backlight->dev;
	backlight->cl.rx_callback = apple_backlight_receive_data;
	backlight->cl.tx_tout = TIMEOUT_MSEC;
	backlight->chan = mbox_request_channel(&backlight->cl, 0);
	if (IS_ERR(backlight->chan)) {
		dev_err(backlight->dev, "couldn't acquire mailbox channel");
		return PTR_ERR(backlight->chan);
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
