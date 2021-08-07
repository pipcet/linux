// SPDX-License-Identifier: GPL-2.0+
/*
 * Driver for work endpoint of the Apple M1 SMC I/O processor.
 *
 * The SMC is a piece of hardware providing read/write/read-with-payload
 * access to many properties identified by fourcc keys.
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

struct smc {
	struct device *dev;
	struct mbox_client cl;
	struct mbox_chan *chan;
	struct work_struct work;
	struct kvbox kvbox;
	struct kvbox_prop *prop;
	bool write;

	spinlock_t lock;
	struct work_struct debug_work;

	struct mutex mutex;

	void *buf;
	dma_addr_t buf_iova;
	size_t buf_size;
	u64 payload;
	u64 endpoint;

	struct completion payload_complete;
};



static void smc_work_func(struct work_struct *work)
{
	struct smc *smc = container_of(work, struct smc, work);

	if (!smc->buf_size) {
		return;
	}

	if (!smc->buf) {
	}
}

static void iowrite_memcpy(void __iomem *to, void *from, size_t count)
{
	while (count--)
		writeb(*((u8 *)from++), to++);
}

static void ioread_memcpy(void *to, void __iomem *from, size_t count)
{
	while (count--)
		*(u8 *)to++ = readb(from++);
}

static void smc_receive_data(struct mbox_client *cl, void *ptr)
{
	struct smc *smc = container_of(cl, struct smc, cl);
	struct apple_mbox_msg *msg = ptr;
	unsigned msg_type = msg->payload & 0xff;
	struct kvbox_prop *prop;

	printk("message of type %02x\n", msg_type);
	switch (msg_type) {
	case 0x18:
		printk(KERN_EMERG "SMC notification\n");
		break;
	default:
	case 0x00:
		smc->payload = msg->payload;
		prop = smc->prop;
		if (prop && !smc->write) {
			if (prop->data_len <= 4) {
				u32 response = smc->payload >> 32;
				memcpy(prop->data, &response, prop->data_len);
			} else {
				ioread_memcpy(prop->data, smc->buf,
					      prop->data_len);
			}
		}
		smc->prop = NULL;
		kvbox_done(&smc->kvbox);
	}
}

static void smc_tx_done(struct mbox_client *cl, void *msg, int code)
{
}

#define CMD_READ           0x10
#define CMD_WRITE          0x11
#define CMD_SHMEM          0x17
#define CMD_READ_PAYLOAD   0x20

static u32 get_key(void *key_ptr, size_t key_len)

{
	u32 key = 0;
	key += ((u8 *)key_ptr)[0]; key <<= 8;
	key += ((u8 *)key_ptr)[1]; key <<= 8;
	key += ((u8 *)key_ptr)[2]; key <<= 8;
	key += ((u8 *)key_ptr)[3];
	return key;
}

static int smc_read(struct kvbox *kvbox, struct kvbox_prop *prop)
{
	struct smc *smc = kvbox->priv;
	size_t key_len = prop->key_len;
	size_t data_len = prop->data_len;
	void *key_ptr = prop->key;
	unsigned long flags;
	struct apple_mbox_msg msg;
	u32 key = get_key(prop->key, prop->key_len);
	int ret;

	msg.endpoint = smc->endpoint;

	if (key_len < 4 || key_len == 5)
		return -EINVAL;

	if (key_len > 255)
		return -EINVAL;

	if (!spin_trylock_irqsave(&smc->lock, flags))
		return -EBUSY;

	if (smc->prop) {
		spin_unlock_irqrestore(&smc->lock, flags);
		return -EBUSY;
	}

	smc->prop = prop;
	smc->write = false;

	if (key_len > 4) {
		msg.payload = (((u64)key << 32) | ((key_len - 5) << 24) |
			       (data_len << 16) | CMD_READ_PAYLOAD);
		iowrite_memcpy(smc->buf, key_ptr + 5, key_len - 5);
	} else {
		msg.payload = (((u64)key << 32) | (data_len << 16) |
			       CMD_READ);
	}

	ret = mbox_send_message(smc->chan, &msg);

	if (ret < 0)
		smc->prop = NULL;

	spin_unlock_irqrestore(&smc->lock, flags);
	return ret;
}

static int smc_write(struct kvbox *kvbox, struct kvbox_prop *prop)
{
	struct smc *smc = kvbox->priv;
	size_t key_len = prop->key_len;
	unsigned long flags;
	struct apple_mbox_msg msg;
	size_t data_len = prop->data_len;
	void *data_ptr = prop->data;
	u32 key = get_key(prop->key, prop->key_len);
	int ret;

	msg.endpoint = smc->endpoint;

	if (key_len != 4)
		return -EINVAL;

	if (!spin_trylock_irqsave(&smc->lock, flags))
		return -EBUSY;

	if (smc->prop) {
		spin_unlock_irqrestore(&smc->lock, flags);
		return -EBUSY;
	}
	smc->prop = prop;
	smc->write = true;

	iowrite_memcpy(smc->buf, data_ptr, data_len);
	msg.payload = (((u64)key << 32) | (data_len << 16) | CMD_WRITE);

	ret = mbox_send_message(smc->chan, &msg);

	if (ret < 0)
		smc->prop = NULL;
	spin_unlock_irqrestore(&smc->lock, flags);
	return ret;
}

static const struct kvbox_ops smc_kvbox_ops = {
	.read = smc_read,
	.write = smc_write,
};

static void smc_complete_callback(void *ptr)
{
	struct completion *c = ptr;
	complete_all(c);
}

static int smc_write_interruptible(struct smc *smc, struct kvbox_prop *prop)
{
	int ret;
	reinit_completion(&smc->payload_complete);
	ret = kvbox_write(&smc->kvbox, prop,
			  smc_complete_callback, &smc->payload_complete);

	if (ret < 0)
		return ret;

	ret = wait_for_completion_interruptible_timeout(&smc->payload_complete,
							5 * HZ);

	if (ret < 0)
		return ret;

	return 0;
}

static int smc_read_interruptible(struct smc *smc, struct kvbox_prop *prop)
{
	int ret;
	reinit_completion(&smc->payload_complete);
	ret = kvbox_read(&smc->kvbox, prop,
			 smc_complete_callback, &smc->payload_complete);

	if (ret < 0)
		return ret;

	ret = wait_for_completion_interruptible_timeout
		(&smc->payload_complete, 5 * HZ);

	if (ret < 0)
		return ret;

	return 0;
}

static int smc_map_buf(struct smc *smc)
{
	int ret;
	dma_addr_t addr;
	struct apple_mbox_msg msg;
	msg.payload = CMD_SHMEM;
	msg.endpoint = smc->endpoint;
	reinit_completion(&smc->payload_complete);
	ret = kvbox_fake_request(&smc->kvbox, smc_complete_callback,
				 &smc->payload_complete);
	if (ret < 0)
		return ret;

	ret = mbox_send_message(smc->chan, &msg);
	if (ret < 0) {
		kvbox_done(&smc->kvbox);
		return ret;
	}
	ret = wait_for_completion_interruptible_timeout
		(&smc->payload_complete, 5 * HZ);

	if (ret < 0)
		return ret;

	addr = smc->payload;

	smc->buf = devm_ioremap(smc->dev, addr, 0x4000);
	if (!smc->buf)
		return -ENOMEM;

	return 0;
}

struct smc_adc {
	struct smc *smc;
	u32 key;
};

static int smc_adc_set_key(struct smc_adc *adc, u32 key)
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
	ret = smc_write_interruptible(adc->smc, &prop);

	return ret;
}

static void smc_adc_probe(struct platform_device *pdev, struct smc *smc)
{
	struct smc_adc *adc;
	u32 nkeys;
	u32 i;
	int ret;
	struct kvbox_prop prop;

	adc = devm_kzalloc(&pdev->dev, sizeof *adc, GFP_KERNEL);

	adc->smc = smc;

	prop.key = "aDC#";
	prop.key_len = 4;
	prop.data = &nkeys;
	prop.data_len = 4;
	ret = smc_read_interruptible(smc, &prop);;
	if (ret < 0)
		return;

	printk("have %08x keys, enumerating:\n", nkeys);
	nkeys = 0x7f;

	for (i = 0; i < nkeys; i++) {
		u32 key = 0;
		struct kvbox_prop prop;
		char prop_key[16] = "aDC?/";
		int ret;

		prop.key = prop_key;
		prop.key_len = 9;
		prop.data = &key;
		prop.data_len = 4;

		memcpy(prop_key + 5, &i, sizeof i);
		ret = smc_read_interruptible(smc, &prop);

		printk("key %c%c%c%c", (key>>24),
		       (key >> 16) & 0xff, (key >> 8) & 0xff, key & 0xff);
	}
}

static int smc_probe(struct platform_device *pdev)
{
	struct smc *smc;
	int ret;
	struct kvbox_prop prop;
	smc = devm_kzalloc(&pdev->dev, sizeof *smc, GFP_KERNEL);
	if (!smc)
		return -ENOMEM;

	smc->endpoint = 0x20;
	smc->dev = &pdev->dev;
	kvbox_register(&smc->kvbox);
	smc->kvbox.dev = smc->dev;
	smc->kvbox.ops = &smc_kvbox_ops;
	INIT_LIST_HEAD(&smc->kvbox.requests);
	smc->kvbox.priv = smc;
	smc->cl.dev = smc->dev;
	smc->cl.rx_callback = smc_receive_data;
	smc->cl.tx_done = smc_tx_done;
	smc->cl.tx_tout = TIMEOUT_MSEC;

	smc->chan = mbox_request_channel(&smc->cl, 0);
	if (IS_ERR(smc->chan))
		return PTR_ERR(smc->chan);

	mutex_init(&smc->mutex);
	mutex_lock(&smc->mutex);

	init_completion(&smc->payload_complete);
	ret = smc_map_buf(smc);
	if (ret < 0)
		return ret;

	prop.key = "NTAP";
	prop.key_len = 4;
	prop.data = "\001";
	prop.data_len = 1;

	ret = smc_write_interruptible(smc, &prop);
	mutex_unlock(&smc->mutex);
	if (ret < 0)
		return ret;

	ret = of_platform_populate(smc->dev->of_node, NULL, NULL, smc->dev);
	if (ret)
		return ret;

	return 0;
}

static const struct of_device_id smc_of_match[] = {
	{ .compatible = "apple,apple-asc-smc" },
	{ },
};

MODULE_DEVICE_TABLE(of, smc_of_match);

static struct platform_driver smc_platform_driver = {
	.driver = {
		.name = "apple-asc-smc",
		.of_match_table = smc_of_match,
        },
	.probe = smc_probe,
};
module_platform_driver(smc_platform_driver);

MODULE_DESCRIPTION("M1 SMC IOP driver");
MODULE_LICENSE("GPL");
