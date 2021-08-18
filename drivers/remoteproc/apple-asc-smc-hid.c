#include <linux/apple-asc.h>
#include <linux/input.h>
#include <linux/platform_device.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/kvbox.h>

#define ASC_POWER_DOWN		0x7201060100000018
#define ASC_POWER_UP		0x7201060000000018
#define ASC_POWER_DOWN_2	0x7201000100000018
#define ASC_POWER_UP_2		0x7201000000000018
#define ASC_LID_CLOSE		0x7203010000000018
#define ASC_LID_OPEN		0x7203000100000018

struct hid {
	struct mbox_chan *chan;
	struct mbox_client cl;
	struct input_dev *input;

	struct kvbox *kvbox;

	struct kvbox_prop mbsw_prop;
	struct kvbox_prop msld_prop;
};

static void hid_power_button_cb(void *ptr)
{
	struct hid *hid = ptr;
	u32 val;
	memcpy(&val, hid->mbsw_prop.data, sizeof val);
	input_report_key(hid->input, /* XXX KEY_POWER */ KEY_SYSRQ, val != 0);
	input_sync(hid->input);
}

static void hid_lid_switch_cb(void *ptr)
{
	struct hid *hid = ptr;
	u32 val;
	memcpy(&val, hid->msld_prop.data, sizeof val);
	input_report_switch(hid->input, SW_LID, val != 0);
	input_sync(hid->input);
}

static void update_power_button(struct hid *hid)
{
	kvbox_read(hid->kvbox, &hid->mbsw_prop, hid_power_button_cb, hid);
}

static void update_lid_switch(struct hid *hid)
{
	kvbox_read(hid->kvbox, &hid->msld_prop, hid_lid_switch_cb, hid);
}

static void hid_receive_data(struct mbox_client *cl, void *ptr)
{
	struct hid *hid = container_of(cl, struct hid, cl);
	struct apple_mbox_msg *msg = ptr;

	switch (msg->payload) {
	case ASC_POWER_DOWN:
	case ASC_POWER_DOWN_2:
	case ASC_POWER_UP:
	case ASC_POWER_UP_2:
		update_power_button(hid);
		break;
	case ASC_LID_CLOSE:
	case ASC_LID_OPEN:
		update_lid_switch(hid);
		break;
	default:
		dev_err(hid->cl.dev, "unknown payload %016llx\n",
			msg->payload);
		update_power_button(hid);
		update_lid_switch(hid);
	}
}

static int hid_probe(struct platform_device *pdev)
{
	struct hid *hid = devm_kzalloc(&pdev->dev, sizeof(*hid), GFP_KERNEL);
	int ret;

	if (!hid)
		return -ENOMEM;

	hid->input = input_allocate_device();
	if (!hid->input)
		return -ENOMEM;

	hid->input->name = devm_kasprintf(&pdev->dev, GFP_KERNEL, "SMCHID");
	hid->input->phys = devm_kasprintf(&pdev->dev, GFP_KERNEL, "SMCHID");
	hid->input->dev.parent = &pdev->dev;
	input_set_capability(hid->input, EV_KEY, KEY_POWER);
	input_set_capability(hid->input, EV_SW, SW_LID);
	input_set_drvdata(hid->input, hid);

	hid->cl.dev = &pdev->dev;
	hid->cl.rx_callback = hid_receive_data;
	hid->chan = mbox_request_channel(&hid->cl, 0);

	if (IS_ERR(hid->chan))
		return PTR_ERR(hid->chan);

	hid->kvbox = kvbox_request(&pdev->dev, 0);
	if (IS_ERR(hid->kvbox))
		return PTR_ERR(hid->kvbox);

	hid->mbsw_prop.key = "MBSW";
	hid->mbsw_prop.key_len = 4;
	hid->mbsw_prop.data = devm_kzalloc(&pdev->dev, 4, GFP_KERNEL);
	hid->mbsw_prop.data_len = 4;

	hid->msld_prop.key = "MSLD";
	hid->msld_prop.key_len = 4;
	hid->msld_prop.data = devm_kzalloc(&pdev->dev, 4, GFP_KERNEL);
	hid->msld_prop.data_len = 4;

	ret = input_register_device(hid->input);
	if (ret < 0)
		return ret;

	return 0;
}

static const struct of_device_id hid_of_match[] = {
	{ .compatible = "apple,apple-asc-smc-hid" },
	{ },
};

MODULE_DEVICE_TABLE(of, hid_of_match);

static struct platform_driver hid_platform_driver = {
	.driver = {
		.name = "apple-asc-smc-hid",
		.of_match_table = hid_of_match,
        },
	.probe = hid_probe,
};
module_platform_driver(hid_platform_driver);

MODULE_DESCRIPTION("M1 SMC HID driver");
MODULE_LICENSE("GPL");
