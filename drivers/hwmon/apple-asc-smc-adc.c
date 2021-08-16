// SPDX-License-Identifier: GPL-2.0+
/*
 * Driver for work endpoint of the Apple M1 SMC I/O processor.
 *
 * The SMC is a piece of "hardware" providing
 * read/write/read-with-payload access to many properties identified
 * by fourcc keys.
 *
 * Copyright (C) 2021 Pip Cet <pipcet@gmail.com>
 */

#include <linux/delay.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/mailbox_client.h>
#include <linux/module.h>
#include <linux/dma-mapping.h>
#include <linux/wait.h>
#include <linux/completion.h>
#include <linux/io.h>
#include <linux/mutex.h>
#include <linux/slab.h>

#include "kvbox.h"

#define TIMEOUT_MSEC 800

#define CMD_READ           0x10
#define CMD_WRITE          0x11
#define CMD_KEY_BY_INDEX   0x12
#define CMD_KEY_INFO       0x13
#define CMD_SHMEM          0x17
#define CMD_READ_PAYLOAD   0x20

#define STATUS_MASK        0xff
#define STATUS_OKAY        0x00
#define STATUS_NOTIFY      0x18 /* asynchronous */
#define STATUS_ERROR_MASK  0x80

struct apple_mbox_msg {
	u64 payload;
	u64 endpoint;
};

struct apple_smc_msg {
	struct apple_mbox_msg query;
	struct apple_mbox_msg response;
	void *inbuf;
	size_t inbuf_size;
	void *outbuf;
	size_t outbuf_size;
};

enum adc_state {
	ADC_READY,
	ADC_SWITCH_KEYS,
	ADC_WARMUP,
};

struct adc {
	struct device *dev;
	struct kvbox *smc;
	struct kvbox kvbox;
	struct kvbox_prop *prop;
	struct kvbox_prop smc_prop;
	enum adc_state state;
	u32 key;
};

static u32 get_key(const void *key_ptr, size_t key_len)

{
	u32 key = 0;
	key += ((const u8 *)key_ptr)[0]; key <<= 8;
	key += ((const u8 *)key_ptr)[1]; key <<= 8;
	key += ((const u8 *)key_ptr)[2]; key <<= 8;
	key += ((const u8 *)key_ptr)[3];
	return key;
}

static void adc_start_warmup(struct adc *adc)
{
}

static void adc_callback(void *ptr)
{
	struct adc *adc = ptr;
	switch (adc->state) {
	case ADC_READY:
		BUG_ON(!adc->prop);
		kvbox_done(&adc->kvbox);
		break;
	case ADC_SWITCH_KEYS:
		adc_start_warmup(adc);
		adc->state = ADC_WARMUP;
		break;
	case ADC_WARMUP:
		BUG();
		break;
	}
}

static int adc_read(struct kvbox *kvbox, struct kvbox_prop *prop)
{
	struct adc *adc = kvbox->priv;
	struct kvbox_prop *smc_prop;
	size_t key_len = prop->key_len;
	size_t data_len = prop->data_len;
	const void *key_ptr = prop->key;
	unsigned long flags;
	u32 key = get_key(prop->key, prop->key_len);
	int ret;

	if (adc->state != ADC_READY)
		return -EBUSY;

	if (key_len != 4)
		return -EINVAL;

	if (adc->prop)
		return -EBUSY;

	adc->prop = prop;

	ret = -ENODEV;

	if (ret < 0)
		adc->prop = NULL;

	return ret;
}

static const struct kvbox_ops adc_kvbox_ops = {
	.read = adc_read,
};

static int adc_set_key(struct adc *adc, u32 key)
{
	int ret;
	struct kvbox_prop prop;
	if (adc->key == key)
		return 0;

	adc->key = key;

	prop.key = "aDC!";
	prop.key_len = 4;
	prop.data = &adc->key;
	prop.data_len = 4;
	ret = kvbox_write_interruptible(adc->smc, &prop);

	return ret;
}

static int adc_probe(struct platform_device *pdev)
{
	struct adc *adc;
	u32 nkeys;
	u32 i;
	int ret;
	struct kvbox_prop prop;

	adc = devm_kzalloc(&pdev->dev, sizeof *adc, GFP_KERNEL);
	adc->dev = &pdev->dev;

	adc->smc = kvbox_request(adc->dev, 0);
	if (IS_ERR(adc->smc))
		return PTR_ERR(adc->smc);

	prop.key = "aDC#";
	prop.key_len = 4;
	prop.data = &nkeys;
	prop.data_len = 4;
	ret = kvbox_read_interruptible(adc->smc, &prop);
	if (ret < 0)
		return ret;

	printk("have %08x keys, enumerating:\n", nkeys);
	adc->kvbox.dev = adc->dev;
	adc->kvbox.ops = &adc_kvbox_ops;
	adc->kvbox.known_props = devm_kcalloc
		(adc->dev, nkeys, sizeof adc->kvbox.known_props[0],
		 GFP_KERNEL);
	adc->kvbox.num_known_props = nkeys;
	INIT_LIST_HEAD(&adc->kvbox.requests);
	adc->kvbox.priv = adc;

	for (i = 0; i < nkeys; i++) {
		u32 key = 0;
		struct kvbox_prop prop;
		char *prop_key = devm_kasprintf(adc->dev, GFP_KERNEL,
						"aDC?-%08x", i);
		int ret;

		prop.key = prop_key;
		prop.key_len = strlen(prop_key);
		prop.data = &key;
		prop.data_len = 4;

		ret = kvbox_read_interruptible(adc->smc, &prop);
		if (ret < 0)
			return ret;

		adc->kvbox.known_props[i].key =
			devm_kasprintf(adc->dev, GFP_KERNEL, "%c%c%c%c",
				       (key >> 24) & 0xff,
				       (key >> 16) & 0xff,
				       (key >>  8) & 0xff,
				       key & 0xff);
		adc->kvbox.known_props[i].key_len = 4;
		adc->kvbox.known_props[i].data_len = 8;
		adc->kvbox.known_props[i].type = "ioft";

		devm_kfree(adc->dev, prop_key);
	}

	kvbox_register(&adc->kvbox);

	return 0;
}

static const struct of_device_id adc_of_match[] = {
	{ .compatible = "apple,apple-asc-smc-adc" },
	{ },
};

MODULE_DEVICE_TABLE(of, adc_of_match);

static struct platform_driver adc_platform_driver = {
	.driver = {
		.name = "apple-asc-smc-adc",
		.of_match_table = adc_of_match,
        },
	.probe = adc_probe,
};
module_platform_driver(adc_platform_driver);

MODULE_DESCRIPTION("M1 SMC ADC driver");
MODULE_LICENSE("GPL");
