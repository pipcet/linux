// SPDX-License-Identifier: GPL-2.0+
/*
 * Mailbox driver for Apple M1 hardware mailboxes. This provides a
 * single-channel mailbox abstracting just the mailbox hardware,
 * without interpreting the protocol (including the bits added by the
 * actual mailbox) in any way.
 *
 * The actual mailbox protocol interprets part of the mailbox message
 * as an endpoint, but it does not map well to a multi-channel
 * mailbox: there's only a single queue shared between all endpoints.
 *
 * The idea is that a second driver will then funnel a number of
 * virtual, infallible mailboxes into this single, fallible one.
 *
 * Currently, the driver does not ever queue more than one outgoing
 * message, even though the mailbox hardware supports this.
 *
 * The hardware appears to be almost perfectly symmetrical: you can
 * read the first queue at +0x810, though usually the CPU only writes
 * it; you can write the second queue at +0x820, though usually the
 * CPU only reads it, and I suspect the four interrupts expose both
 * directions of the mailbox, which is why we only use two of them.
 *
 * Copyright (C) 2021 Pip Cet <pipcet@gmail.com>
 */

#include <linux/module.h>
#include <linux/mailbox_controller.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_device.h>

#include <linux/dma-mapping.h> /* XXX */

/* There's only one IRQ which we can usefully disable: the one
 * telling us the CPU-to-IOP queue is empty. We only care
 * after writing something to it, so the IRQ is initialized
 * with this flag set. */
struct apple_mailbox {
	struct device *dev;
	spinlock_t lock;
	bool busy;
	void __iomem *reg;
	struct mbox_controller mbox_controller;
	struct mbox_chan mbox_chan;
	int irq_cpu_to_iop_empty;
	int irq_iop_to_cpu_nonempty;

	bool irq_disabled;
};

#define REG_CPU_TO_IOP          0x110
#define REG_IOP_TO_CPU          0x114
#define   REG_EMPTY             BIT(17)

#define REG_SEND_CPU_TO_IOP	0x800
#define REG_RECV_CPU_TO_IOP     0x810
#define REG_SEND_IOP_TO_CPU	0x820
#define REG_RECV_IOP_TO_CPU     0x830

static void apple_mailbox_send_cpu_to_iop(struct apple_mailbox *mb,
					  void *msg)
{
	u64 msg_data[2];
	memcpy(msg_data, msg, sizeof(msg_data));
	if (0) dev_err(mb->mbox_controller.dev,
				   "> %016llx %016llx [%016llx]\n",
				   msg_data[0], msg_data[1], (u64)mb);
	writeq(msg_data[0], mb->reg + REG_SEND_CPU_TO_IOP);
	writeq(msg_data[1], mb->reg + REG_SEND_CPU_TO_IOP + 8);
}

static bool apple_mailbox_cpu_to_iop_empty(struct apple_mailbox *mb)
{
	return readl(mb->reg + REG_CPU_TO_IOP) & REG_EMPTY;
}

static bool apple_mailbox_iop_to_cpu_empty(struct apple_mailbox *mb)
{
	return readl(mb->reg + REG_IOP_TO_CPU) & REG_EMPTY;
}

static void apple_mailbox_disable_irq(struct apple_mailbox *mb)
{
	if (!mb->irq_disabled) {
		mb->irq_disabled = true;
		disable_irq_nosync(mb->irq_cpu_to_iop_empty);
	}
}

static void apple_mailbox_enable_irq(struct apple_mailbox *mb)
{
	if (mb->irq_disabled) {
		mb->irq_disabled = false;
		enable_irq(mb->irq_cpu_to_iop_empty);
	}
}

static irqreturn_t apple_mailbox_irq_cpu_to_iop_empty(int irq, void *ptr)
{
	struct apple_mailbox *mb = ptr;
	unsigned long flags;
	bool sent = false;

	if (!apple_mailbox_cpu_to_iop_empty(mb))
		return IRQ_NONE;

	spin_lock_irqsave(&mb->lock, flags);
	apple_mailbox_disable_irq(mb);
	sent = mb->busy;
	mb->busy = false;
	spin_unlock_irqrestore(&mb->lock, flags);

	if (sent)
		mbox_chan_txdone(&mb->mbox_chan, 0);

	return IRQ_HANDLED;
}

static irqreturn_t apple_mailbox_irq_iop_to_cpu_nonempty(int irq, void *ptr)
{
	struct apple_mailbox *mb = ptr;
	unsigned long flags;
	u64 msg_data[2];

	spin_lock_irqsave(&mb->lock, flags);

	if (apple_mailbox_iop_to_cpu_empty(mb)) {
		spin_unlock_irqrestore(&mb->lock, flags);
		return IRQ_NONE;
	}

	msg_data[0] = readq(mb->reg + REG_RECV_IOP_TO_CPU);
	msg_data[1] = readq(mb->reg + REG_RECV_IOP_TO_CPU + 8);
	if (0) dev_err(mb->mbox_controller.dev,
				   "< %016llx %016llx [%016llx]\n",
				   msg_data[0], msg_data[1], (u64)mb);

	spin_unlock_irqrestore(&mb->lock, flags);

	mbox_chan_received_data(&mb->mbox_chan, msg_data);

	return IRQ_HANDLED;
}

static int apple_mailbox_send_data(struct mbox_chan *chan, void *msg)
{
	struct apple_mailbox *mb = chan->con_priv;
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&mb->lock, flags);

	if (mb->busy) {
		ret = -EBUSY;
	} else {
		if (apple_mailbox_cpu_to_iop_empty(mb)) {
			apple_mailbox_send_cpu_to_iop(mb, msg);
			mb->busy = true;
			apple_mailbox_enable_irq(mb);
		} else {
			ret = -EBUSY;
		}
	}

	spin_unlock_irqrestore(&mb->lock, flags);

	return ret;
}

static const struct mbox_chan_ops apple_mailbox_ops = {
	.send_data = apple_mailbox_send_data,
};

static int apple_mailbox_probe(struct platform_device *pdev)
{
	struct apple_mailbox *mb;
	struct resource *res;
	int ret;

	mb = devm_kzalloc(&pdev->dev, sizeof *mb, GFP_KERNEL);
	if (!mb)
		return ENOMEM;

	mb->dev = &pdev->dev;
	dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));

	spin_lock_init(&mb->lock);
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res)
		return -ENODEV;

	mb->reg = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(mb->reg))
		return PTR_ERR(mb->reg);

	mb->irq_cpu_to_iop_empty = platform_get_irq(pdev, 0);
	mb->irq_iop_to_cpu_nonempty = platform_get_irq(pdev, 1);

	ret = devm_request_irq(&pdev->dev, mb->irq_cpu_to_iop_empty,
			       apple_mailbox_irq_cpu_to_iop_empty,
			       IRQF_NO_AUTOEN,
			       dev_name(&pdev->dev), mb);
	if (ret < 0)
		return ret;

	/* XXX ask marcan whether this is a bug in the AIC driver */
	irq_set_status_flags(mb->irq_cpu_to_iop_empty, IRQ_DISABLE_UNLAZY);
	mb->irq_disabled = true;

	ret = devm_request_irq(&pdev->dev, mb->irq_iop_to_cpu_nonempty,
			       apple_mailbox_irq_iop_to_cpu_nonempty, 0,
			       dev_name(&pdev->dev), mb);
	if (ret < 0)
		return ret;

	mb->mbox_controller.dev = &pdev->dev;
	mb->mbox_controller.chans = &mb->mbox_chan;
	mb->mbox_controller.num_chans = 1;
	mb->mbox_controller.txdone_irq = true;
	mb->mbox_controller.ops = &apple_mailbox_ops;

	mb->mbox_chan.con_priv = mb;

	ret = devm_mbox_controller_register(&pdev->dev, &mb->mbox_controller);
	if (ret < 0)
		return ret;

	return 0;
}

static const struct of_device_id apple_mailbox_of_match[] = {
	{ .compatible = "apple,apple-mailbox" },
	{ },
};
MODULE_DEVICE_TABLE(of, apple_mailbox_of_match);

static struct platform_driver apple_mailbox_platform_driver = {
	.driver = {
		.name = "apple-mailbox",
		.of_match_table = apple_mailbox_of_match,
	},
	.probe = apple_mailbox_probe,
};
module_platform_driver(apple_mailbox_platform_driver);
MODULE_DESCRIPTION("Apple M1 mailbox driver");
MODULE_LICENSE("GPL");
