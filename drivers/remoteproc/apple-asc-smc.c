// SPDX-License-Identifier: GPL-2.0+
/*
 * Driver for work endpoint of the Apple M1 SMC I/O processor.
 *
 * The SMC is a piece of hardware providing read/write/read-with-payload
 * access to many properties identified by fourcc keys.
 *
 * Copyright (C) 2021 Pip Cet <pipcet@gmail.com>
 */

#include <linux/apple-asc.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/kvbox.h>
#include <linux/mailbox_client.h>
#include <linux/mailbox_controller.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/wait.h>

#define NUM_SMC_NOTIFICATION_CHANS 3

struct smc {
	struct device *dev;
	struct mbox_client cl;
	struct mbox_controller mbox_controller;
	struct mbox_chan chans[NUM_SMC_NOTIFICATION_CHANS];
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
	struct irq_domain *irq_domain;
	struct irq_chip irq_chip;
};

static void dump_buf(const __iomem void *buf)
{
	return;
	static u32 b[32];
	int i;
	for (i = 0; i < 32; i++)
		b[i] = readl(buf + 4 * i);
	print_hex_dump(KERN_EMERG, "message:", DUMP_PREFIX_NONE,
		       16, 1, b, 128, true);
	printk("---");
}

static void iowrite_memcpy(void __iomem *to, const void *from, size_t count)
{
	writel(0xffffffff, to);
	asm volatile("dsb sy");
	dump_buf(to);
	while (count--) {
		do {
	asm volatile("dsb sy");
			asm volatile("esb"); asm volatile("dmb sy");
	asm volatile("dsb sy");
			asm volatile("esb"); asm volatile("dmb sy");
			writeb(*((u8 *)from), to);
	asm volatile("dsb sy");
			asm volatile("esb"); asm volatile("dmb sy");
	asm volatile("dsb sy");
			asm volatile("esb"); asm volatile("dmb sy");
		} while (readb(to) != *(u8 *)from && 0);
	asm volatile("dsb sy");
		from++;
		to++;
	}
}

static void ioread_memcpy(void *to, const void __iomem *from, size_t count)
{
	while (count--)
		*(u8 *)to++ = readb(from++);
}

static void smc_handle_notification(struct smc *smc, struct apple_mbox_msg *msg)
{
	struct mbox_chan *chan;
	switch (msg->payload >> 56) {
	case 0x72:
		chan = &smc->chans[0];
		break;
	case 0x71:
		chan = &smc->chans[1];
		break;
	default:
		chan = &smc->chans[2];
		break;
	}

	if (chan->cl) {
		mbox_chan_received_data(chan, msg);
	} else {
		dev_err(smc->dev,
			"%016llx feels like an unwanted child\n",
			msg->payload);
	}
}

static void smc_receive_data(struct mbox_client *cl, void *ptr)
{
	struct smc *smc = container_of(cl, struct smc, cl);
	struct apple_mbox_msg *msg = ptr;
	unsigned msg_type = msg->payload & 0xff;
	struct kvbox_prop *prop;

	printk("message %016llx\n", msg->payload);
	if (0) printk("message of type %02x\n", msg_type);
	switch (msg_type) {
	case 0x18:
		smc_handle_notification(smc, msg);
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
#define CMD_KEY_BY_INDEX   0x12
#define CMD_KEY_INFO       0x13
#define CMD_SHMEM          0x17
#define CMD_READ_PAYLOAD   0x20

static int parse_le_chunks(struct smc *smc,
			   const char *chunks, void **payload, size_t *payload_len)
{
	const char *beg = chunks;
	char *end;
	size_t total_len = 0;
	u8 *payload_ptr;
	do {
		size_t chunk_len;
		simple_strtoull(beg, &end, 16);
		chunk_len = end - beg;
		if (chunk_len & 1)
			return -EINVAL;
		if (chunk_len == 0)
			return -EINVAL;
		total_len += chunk_len/2;
	} while (end[0] == '-' && (beg = end+1));

	if (end[0])
		return -EINVAL;

	*payload = devm_kzalloc(smc->dev, total_len, GFP_KERNEL);
	payload_ptr = *payload;
	beg = chunks;
	do {
		unsigned long long payload_chunk =
			simple_strtoull(beg, &end, 16);
		size_t chunk_len = end - beg;
		while (chunk_len > 0) {
			chunk_len -= 2;
			*payload_ptr++ = (payload_chunk & 0xff);
			payload_chunk >>= 8;
		}
	} while (end[0] && (beg = end+1));

	*payload_len = total_len;

	return 0;
}

static int get_key(struct smc *smc, const void *key_ptr, size_t key_len,
		   u32 *key, void **payload, size_t *payload_len)

{
	const char *keystr = key_ptr;
	int ret;
	if (key_len < 4) {
		return -EINVAL;
	} else if (key_len == 4) {
		*payload_len = 0;
	} else if (keystr[key_len]) {
		void *tmp_key = devm_kzalloc(smc->dev, key_len+1, GFP_KERNEL);
		memcpy(tmp_key, key, key_len);
		ret = get_key(smc, tmp_key, key_len, key, payload, payload_len);
		devm_kfree(smc->dev, tmp_key);
		return ret;
	} else if (key_len > 5 && keystr[4] == '-') {
		ret = parse_le_chunks(smc, keystr + 5, payload, payload_len);
		if (ret < 0)
			return ret;
	} else {
		return -EINVAL;
	}

	memcpy(key, keystr, 4);
	*key = swab32(*key);
	return 0;
}

static int smc_read(struct kvbox *kvbox, struct kvbox_prop *prop)
{
	struct smc *smc = kvbox->priv;
	size_t key_len = prop->key_len;
	size_t data_len = prop->data_len;
	unsigned long flags;
	struct apple_mbox_msg msg;
	void *payload = NULL;
	size_t payload_len = 0;
	u32 key;
	int ret = get_key(smc, prop->key, prop->key_len,
			  &key, &payload, &payload_len);

	if (ret < 0)
		return ret;

	msg.endpoint = smc->endpoint;

	if (!spin_trylock_irqsave(&smc->lock, flags))
		return -EBUSY;

	if (smc->prop) {
		spin_unlock_irqrestore(&smc->lock, flags);
		return -EBUSY;
	}

	smc->prop = prop;
	smc->write = false;

	if (key_len > 4) {
		msg.payload = (((u64)key << 32) | (payload_len << 24) |
			       (data_len << 16) | CMD_READ_PAYLOAD);
		iowrite_memcpy(smc->buf, payload, payload_len);
	} else {
		msg.payload = (((u64)key << 32) | (data_len << 16) |
			       CMD_READ);
	}

	ret = mbox_copy_and_send(smc->chan, &msg);

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
	void *payload;
	size_t payload_len = 0;
	u32 key;
	int ret = get_key(smc, prop->key, prop->key_len,
			  &key, &payload, &payload_len);

	if (ret < 0)
		return ret;

	msg.endpoint = smc->endpoint;

	if (key_len < 4)
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

	ret = mbox_copy_and_send(smc->chan, &msg);

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
	struct completion c;
	init_completion(&c);
	ret = kvbox_write(&smc->kvbox, prop, smc_complete_callback, &c);

	if (ret < 0)
		return ret;

	ret = 0; wait_for_completion(&c);

	if (ret < 0)
		return ret;

	return 0;
}

static int smc_read_interruptible(struct smc *smc, struct kvbox_prop *prop)
{
	int ret;
	struct completion c;
	init_completion(&c);
	ret = kvbox_read(&smc->kvbox, prop, smc_complete_callback, &c);

	if (ret < 0)
		return ret;

	ret = 0; wait_for_completion(&c);

	if (ret < 0)
		return ret;

	return 0;
}

static int smc_map_buf(struct smc *smc)
{
	int ret;
	dma_addr_t addr;
	struct apple_mbox_msg msg;
	struct completion c;
	msg.payload = CMD_SHMEM;
	msg.endpoint = smc->endpoint;
	init_completion(&c);
	ret = kvbox_fake_request(&smc->kvbox, smc_complete_callback, &c);
	if (ret < 0)
		return ret;

	ret = mbox_copy_and_send(smc->chan, &msg);
	if (ret < 0) {
		kvbox_done(&smc->kvbox);
		return ret;
	}
	ret = 0; wait_for_completion(&c);

	if (ret < 0)
		return ret;

	addr = smc->payload;

	smc->buf = devm_ioremap_np(smc->dev, addr, 0x4000);
	if (!smc->buf)
		return -ENOMEM;

	return 0;
}

static int smc_enumerate(struct smc *smc)
{
	int ret;
	u32 count;
	struct kvbox_prop prop;
	u32 key;
	struct apple_mbox_msg msg;
	u64 i;
	struct kvbox_prop *props;
	struct completion c;

	init_completion(&c);

	prop.key = "#KEY";
	prop.key_len = 4;
	prop.data = &count;
	prop.data_len = 4;
	ret = smc_read_interruptible(smc, &prop);
	if (ret < 0)
		return ret;

	count = swab32(count); /* Thank you, Apple. Thapple. */

	props = devm_kcalloc(smc->dev, count, sizeof props[0], GFP_KERNEL);
	if (!props)
		return -ENOMEM;

	for (i = 0; i < count; i++) {
		void *key_ptr;

		ret = kvbox_fake_request(&smc->kvbox, smc_complete_callback,
					 &c);
		if (ret < 0)
			return ret;

		msg.payload = CMD_KEY_BY_INDEX | (i << 32);
		msg.endpoint = smc->endpoint;

		reinit_completion(&c);
		ret = mbox_copy_and_send(smc->chan, &msg);
		if (ret < 0) {
			kvbox_done(&smc->kvbox);
			return ret;
		}

		wait_for_completion(&c);

		key = smc->payload >> 32;

		key_ptr = devm_kzalloc(smc->dev, 4, GFP_KERNEL);
		if (!key_ptr)
			return -ENOMEM;
		memcpy(key_ptr, &key, 4);
		props[i].key = key_ptr;
		props[i].key_len = 4;

		props[i].data = NULL;
		props[i].data_len = 0;

		props[i].type = NULL;
		props[i].extra = NULL;

		msg.payload = CMD_KEY_INFO | (6 << 16) | ((u64)swab32(key) << 32);
		msg.endpoint = smc->endpoint;

		reinit_completion(&c);
		ret = kvbox_fake_request(&smc->kvbox, smc_complete_callback,
					 &c);

		if (ret < 0)
			return ret;

		ret = mbox_copy_and_send(smc->chan, &msg);
		if (ret < 0) {
			kvbox_done(&smc->kvbox);
			return ret;
		}

		wait_for_completion(&c);

		props[i].type = devm_kasprintf(smc->dev, GFP_KERNEL,
					       "%c%c%c%c",
					       readb(smc->buf + 1),
					       readb(smc->buf + 2),
					       readb(smc->buf + 3),
					       readb(smc->buf + 4));

		props[i].extra = devm_kasprintf(smc->dev, GFP_KERNEL,
						"flags %02x",
						readb(smc->buf + 5));

		if (readb(smc->buf + 5) == 0xf0) {
			props[i].key = devm_kasprintf(smc->dev, GFP_KERNEL,
						      "%.*s-%08x",
						      4, (const char *)props[i].key, U32_MAX);
			props[i].key_len = strlen(props[i].key);
		}

		props[i].data_len = readb(smc->buf);
	}

	smc->kvbox.known_props = props;
	smc->kvbox.num_known_props = count;

	return 0;
}

static int smc_irq_map(struct irq_domain *d, unsigned int irq, irq_hw_number_t hwirq)
{
	struct smc *smc = d->host_data;

	irq_set_chip_data(irq, smc);
	/* XXX irq_set_lockdep_class */
	irq_set_chip_and_handler(irq, &smc->irq_chip, handle_simple_irq);
	irq_set_noprobe(irq);

	return 0;
}

static void smc_irq_unmap(struct irq_domain *d, unsigned int irq)
{
	irq_set_chip_and_handler(irq, NULL, NULL);
	irq_set_chip_data(irq, NULL);
}

static const struct irq_domain_ops smc_domain_ops = {
	.map = smc_irq_map,
	.unmap = smc_irq_unmap,
	.xlate = irq_domain_xlate_onecell,
};

static void irq_mask_unmask_noop(struct irq_data *d)
{
}

static const struct mbox_chan_ops smc_mbox_ops = {
};

static int smc_probe(struct platform_device *pdev)
{
	struct smc *smc;
	int ret;
	u32 endpoint;
	struct kvbox_prop prop;

	smc = devm_kzalloc(&pdev->dev, sizeof *smc, GFP_KERNEL);
	if (!smc)
		return -ENOMEM;

	smc->dev = &pdev->dev;
	smc->kvbox.dev = smc->dev;
	smc->kvbox.ops = &smc_kvbox_ops;
	spin_lock_init(&smc->lock);
	INIT_LIST_HEAD(&smc->kvbox.requests);
	smc->kvbox.priv = smc;
	smc->cl.dev = smc->dev;
	smc->cl.rx_callback = smc_receive_data;
	smc->cl.tx_done = smc_tx_done;
	smc->cl.tx_tout = ASC_TIMEOUT_MSEC;

	smc->chan = mbox_request_channel(&smc->cl, 0);
	if (IS_ERR(smc->chan))
		return PTR_ERR(smc->chan);

	ret = of_property_read_u32_index(smc->dev->of_node, "mboxes", 1, &endpoint);
	if (ret)
		return ret;

	smc->endpoint = endpoint;
	mutex_init(&smc->mutex);
	mutex_lock(&smc->mutex);

	ret = smc_map_buf(smc);
	if (ret < 0)
		return ret;

	prop.key = "NTAP";
	prop.key_len = 4;
	prop.data = "\001";
	prop.data_len = 1;

	ret = smc_write_interruptible(smc, &prop);
	if (ret < 0)
		return ret;

	smc_enumerate(smc);
	kvbox_register(&smc->kvbox);

	smc->mbox_controller.dev = smc->dev;
	smc->mbox_controller.ops = &smc_mbox_ops;
	smc->mbox_controller.chans = smc->chans;
	smc->mbox_controller.num_chans = NUM_SMC_NOTIFICATION_CHANS;
	devm_mbox_controller_register(smc->dev, &smc->mbox_controller);

	mutex_unlock(&smc->mutex);

	smc->irq_chip.parent_device = smc->dev;
	smc->irq_chip.name = "smc";
	smc->irq_chip.irq_mask = irq_mask_unmask_noop;
	smc->irq_chip.irq_unmask = irq_mask_unmask_noop;
	smc->irq_domain = irq_domain_add_linear(smc->dev->of_node, NUM_SMC_IRQ,
						&smc_domain_ops, smc);

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

MODULE_DESCRIPTION("Apple M1 SMC work endpoint driver");
MODULE_LICENSE("GPL");
