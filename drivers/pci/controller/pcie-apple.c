// SPDX-License-Identifier: GPL-2.0
/*
 * PCIe host bridge driver for Apple system-on-chips.
 *
 * The HW is ECAM compliant, so once the controller is initialized, the driver
 * mostly only needs MSI handling. Initialization requires enabling power and
 * clocks, along with a number of register pokes.
 *
 * Copyright (C) 2021 Alyssa Rosenzweig <alyssa@rosenzweig.io>
 * Copyright (C) 2021 Google LLC
 * Copyright (C) 2021 Corellium LLC
 * Copyright (C) 2021 Mark Kettenis <kettenis@openbsd.org>
 *
 * Author: Alyssa Rosenzweig <alyssa@rosenzweig.io>
 * Author: Marc Zyngier <maz@kernel.org>
 */

#include <linux/kernel.h>
#include <linux/irqdomain.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/of_irq.h>
#include <linux/pci-ecam.h>
#include <linux/iopoll.h>
#include <linux/gpio/consumer.h>

#define CORE_RC_PHYIF_CTL		0x00024
#define   CORE_RC_PHYIF_CTL_RUN		BIT(0)
#define CORE_RC_PHYIF_STAT		0x00028
#define   CORE_RC_PHYIF_STAT_REFCLK	BIT(4)
#define CORE_RC_CTL			0x00050
#define   CORE_RC_CTL_RUN		BIT(0)
#define CORE_RC_STAT			0x00058
#define   CORE_RC_STAT_READY		BIT(0)
#define CORE_FABRIC_STAT		0x04000
#define   CORE_FABRIC_STAT_MASK		0x001F001F
#define CORE_LANE_CFG(port)		(0x84000 + 0x4000 * (port))
#define   CORE_LANE_CFG_REFCLK0REQ	BIT(0)
#define   CORE_LANE_CFG_REFCLK1		BIT(1)
#define   CORE_LANE_CFG_REFCLK0ACK	BIT(2)
#define   CORE_LANE_CFG_REFCLKEN	(BIT(9) | BIT(10))
#define CORE_LANE_CTL(port)		(0x84004 + 0x4000 * (port))
#define   CORE_LANE_CTL_CFGACC		BIT(15)

#define PORT_LTSSMCTL			0x00080
#define   PORT_LTSSMCTL_START		BIT(0)
#define PORT_INTSTAT			0x00100
#define   PORT_INT_TUNNEL_ERR		BIT(31)
#define   PORT_INT_CPL_TIMEOUT		BIT(23)
#define   PORT_INT_RID2SID_MAPERR	BIT(22)
#define   PORT_INT_CPL_ABORT		BIT(21)
#define   PORT_INT_MSI_BAD_DATA		BIT(19)
#define   PORT_INT_MSI_ERR		BIT(18)
#define   PORT_INT_REQADDR_GT32		BIT(17)
#define   PORT_INT_AF_TIMEOUT		BIT(15)
#define   PORT_INT_LINK_DOWN		BIT(14)
#define   PORT_INT_LINK_UP		BIT(12)
#define   PORT_INT_LINK_BWMGMT		BIT(11)
#define   PORT_INT_AER_MASK		(15 << 4)
#define   PORT_INT_PORT_ERR		BIT(4)
#define   PORT_INT_INTx(i)		BIT(i)
#define   PORT_INT_INTxALL		15
#define PORT_INTMSK			0x00104
#define PORT_INTMSKSET			0x00108
#define PORT_INTMSKCLR			0x0010c
#define PORT_MSICFG			0x00124
#define   PORT_MSICFG_EN		BIT(0)
#define   PORT_MSICFG_L2MSINUM_SHIFT	4
#define PORT_MSIBASE			0x00128
#define   PORT_MSIBASE_1_SHIFT		16
#define PORT_MSIADDR			0x00168
#define PORT_LINKSTS			0x00208
#define   PORT_LINKSTS_UP		BIT(0)
#define   PORT_LINKSTS_BUSY		BIT(2)
#define PORT_LINKCMDSTS			0x00210
#define PORT_OUTS_NPREQS		0x00284
#define   PORT_OUTS_NPREQS_REQ		BIT(24)
#define   PORT_OUTS_NPREQS_CPL		BIT(16)
#define PORT_RXWR_FIFO			0x00288
#define   PORT_RXWR_FIFO_HDR		GENMASK(15, 10)
#define   PORT_RXWR_FIFO_DATA		GENMASK(9, 0)
#define PORT_RXRD_FIFO			0x0028C
#define   PORT_RXRD_FIFO_REQ		GENMASK(6, 0)
#define PORT_OUTS_CPLS			0x00290
#define   PORT_OUTS_CPLS_SHRD		GENMASK(14, 8)
#define   PORT_OUTS_CPLS_WAIT		GENMASK(6, 0)
#define PORT_APPCLK			0x00800
#define   PORT_APPCLK_EN		BIT(0)
#define   PORT_APPCLK_CGDIS		BIT(8)
#define PORT_STATUS			0x00804
#define   PORT_STATUS_READY		BIT(0)
#define PORT_REFCLK			0x00810
#define   PORT_REFCLK_EN		BIT(0)
#define   PORT_REFCLK_CGDIS		BIT(8)
#define PORT_PERST			0x00814
#define   PORT_PERST_OFF		BIT(0)
#define PORT_RID2SID(i16)		(0x00828 + 4 * (i16))
#define   PORT_RID2SID_VALID		BIT(31)
#define   PORT_RID2SID_SID_SHIFT	16
#define   PORT_RID2SID_BUS_SHIFT	8
#define   PORT_RID2SID_DEV_SHIFT	3
#define   PORT_RID2SID_FUNC_SHIFT	0
#define PORT_OUTS_PREQS_HDR		0x00980
#define   PORT_OUTS_PREQS_HDR_MASK	GENMASK(9, 0)
#define PORT_OUTS_PREQS_DATA		0x00984
#define   PORT_OUTS_PREQS_DATA_MASK	GENMASK(15, 0)
#define PORT_TUNCTRL			0x00988
#define   PORT_TUNCTRL_PERST_ON		BIT(0)
#define   PORT_TUNCTRL_PERST_ACK_REQ	BIT(1)
#define PORT_TUNSTAT			0x0098c
#define   PORT_TUNSTAT_PERST_ON		BIT(0)
#define   PORT_TUNSTAT_PERST_ACK_PEND	BIT(1)
#define PORT_PREFMEM_ENABLE		0x00994

/* The doorbell address is "well known" */
#define DOORBELL_ADDR			0xfffff000

struct apple_pcie {
	struct mutex		lock;
	struct device		*dev;
	void __iomem            *rc;
	struct irq_domain	*domain;
	unsigned long		*bitmap;
	u32			msi_base;
	u32			nvecs;
};

static inline void rmwl(u32 clr, u32 set, void __iomem *addr)
{
	writel_relaxed((readl_relaxed(addr) & ~clr) | set, addr);
}

static void apple_msi_top_irq_mask(struct irq_data *d)
{
	pci_msi_mask_irq(d);
	irq_chip_mask_parent(d);
}

static void apple_msi_top_irq_unmask(struct irq_data *d)
{
	pci_msi_unmask_irq(d);
	irq_chip_unmask_parent(d);
}

static struct irq_chip apple_msi_top_chip = {
	.name			= "PCIe MSI",
	.irq_mask		= apple_msi_top_irq_mask,
	.irq_unmask		= apple_msi_top_irq_unmask,
	.irq_eoi		= irq_chip_eoi_parent,
	.irq_set_affinity	= irq_chip_set_affinity_parent,
	.irq_set_type		= irq_chip_set_type_parent,
};

static void apple_msi_compose_msg(struct irq_data *data, struct msi_msg *msg)
{
	msg->address_hi = upper_32_bits(DOORBELL_ADDR);
	msg->address_lo = lower_32_bits(DOORBELL_ADDR);
	msg->data = data->hwirq;
}

static struct irq_chip apple_msi_bottom_chip = {
	.name			= "MSI",
	.irq_mask		= irq_chip_mask_parent,
	.irq_unmask		= irq_chip_unmask_parent,
	.irq_eoi		= irq_chip_eoi_parent,
	.irq_set_affinity	= irq_chip_set_affinity_parent,
	.irq_set_type		= irq_chip_set_type_parent,
	.irq_compose_msi_msg	= apple_msi_compose_msg,
};

static int apple_msi_domain_alloc(struct irq_domain *domain, unsigned int virq,
				  unsigned int nr_irqs, void *args)
{
	struct apple_pcie *pcie = domain->host_data;
	struct irq_fwspec fwspec;
	unsigned int i;
	int ret, hwirq;

	mutex_lock(&pcie->lock);

	hwirq = bitmap_find_free_region(pcie->bitmap, pcie->nvecs,
					order_base_2(nr_irqs));

	mutex_unlock(&pcie->lock);

	if (hwirq < 0)
		return -ENOSPC;

	fwspec.fwnode = domain->parent->fwnode;
	fwspec.param_count = 3;
	fwspec.param[0] = 0;
	fwspec.param[1] = hwirq + pcie->msi_base;
	fwspec.param[2] = IRQ_TYPE_EDGE_RISING;

	ret = irq_domain_alloc_irqs_parent(domain, virq, nr_irqs, &fwspec);
	if (ret)
		return ret;

	for (i = 0; i < nr_irqs; i++) {
		irq_domain_set_hwirq_and_chip(domain, virq + i, hwirq + i,
					      &apple_msi_bottom_chip,
					      domain->host_data);
	}

	return 0;
}

static void apple_msi_domain_free(struct irq_domain *domain, unsigned int virq,
				  unsigned int nr_irqs)
{
	struct irq_data *d = irq_domain_get_irq_data(domain, virq);
	struct apple_pcie *pcie = domain->host_data;

	mutex_lock(&pcie->lock);

	bitmap_release_region(pcie->bitmap, d->hwirq, order_base_2(nr_irqs));

	mutex_unlock(&pcie->lock);
}

static const struct irq_domain_ops apple_msi_domain_ops = {
	.alloc	= apple_msi_domain_alloc,
	.free	= apple_msi_domain_free,
};

static struct msi_domain_info apple_msi_info = {
	.flags	= (MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS |
		   MSI_FLAG_MULTI_PCI_MSI | MSI_FLAG_PCI_MSIX),
	.chip	= &apple_msi_top_chip,
};

static int apple_pcie_setup_refclk(void __iomem *rc,
				   void __iomem *port,
				   unsigned int idx)
{
	u32 stat;
	int res;

	res = readl_relaxed_poll_timeout(rc + CORE_RC_PHYIF_STAT, stat,
					 stat & CORE_RC_PHYIF_STAT_REFCLK,
					 100, 50000);
	if (res < 0)
		return res;

	rmwl(0, CORE_LANE_CTL_CFGACC, rc + CORE_LANE_CTL(idx));
	rmwl(0, CORE_LANE_CFG_REFCLK0REQ, rc + CORE_LANE_CFG(idx));

	res = readl_relaxed_poll_timeout(rc + CORE_LANE_CFG(idx), stat,
					 stat & CORE_LANE_CFG_REFCLK0ACK,
					 100, 50000);
	if (res < 0)
		return res;

	rmwl(0, CORE_LANE_CFG_REFCLK1, rc + CORE_LANE_CFG(idx));
	res = readl_relaxed_poll_timeout(rc + CORE_LANE_CFG(idx), stat,
					 stat & CORE_LANE_CFG_REFCLK1,
					 100, 50000);

	if (res < 0)
		return res;

	rmwl(CORE_LANE_CTL_CFGACC, 0, rc + CORE_LANE_CTL(idx));

	/* Flush writes before enabling the clocks */
	dma_wmb();

	rmwl(0, CORE_LANE_CFG_REFCLKEN, rc + CORE_LANE_CFG(idx));
	rmwl(0, PORT_REFCLK_EN, port + PORT_REFCLK);

	return 0;
}

static int apple_pcie_setup_port(struct apple_pcie *pcie,
				 struct gpio_desc *reset,
				 unsigned int i,
				 void __iomem *port)
{
	struct platform_device *platform = to_platform_device(pcie->dev);
	uint32_t stat;
	int ret;

	rmwl(0, PORT_APPCLK_EN, port + PORT_APPCLK);

	ret = apple_pcie_setup_refclk(pcie->rc, port, i);
	if (ret < 0)
		return ret;

	rmwl(0, PORT_PERST_OFF, port + PORT_PERST);
	gpiod_set_value(reset, 1);

	ret = readl_relaxed_poll_timeout(port + PORT_STATUS, stat,
					 stat & PORT_STATUS_READY, 100, 250000);
	if (ret < 0) {
		dev_err(pcie->dev, "port %u ready wait timeout\n", i);
		return ret;
	}

	/* Configure MSIs */
	writel_relaxed(DOORBELL_ADDR, port + PORT_MSIADDR);
	writel_relaxed(0, port + PORT_MSIBASE);

	/* Enable 32 MSIs */
	writel_relaxed((5 << PORT_MSICFG_L2MSINUM_SHIFT) | PORT_MSICFG_EN,
		       port + PORT_MSICFG);

	/* Enable link interrupts */
	writel_relaxed(0xfb512fff, port + PORT_INTMSKSET);

	writel_relaxed(PORT_INT_LINK_UP | PORT_INT_LINK_DOWN |
		       PORT_INT_AF_TIMEOUT | PORT_INT_REQADDR_GT32 |
		       PORT_INT_MSI_ERR | PORT_INT_MSI_BAD_DATA |
		       PORT_INT_CPL_ABORT | PORT_INT_CPL_TIMEOUT | (1 << 26),
		       port + PORT_INTSTAT);

	/* Flush writes and enable the link */
	dma_wmb();
	writel_relaxed(PORT_LTSSMCTL_START, port + PORT_LTSSMCTL);

	return 0;
}

static int apple_msi_init(struct apple_pcie *pcie)
{
	struct fwnode_handle *fwnode = dev_fwnode(pcie->dev);
	struct device_node *parent_intc;
	struct irq_domain *parent;
	int ret;

	ret = of_property_read_u32_index(to_of_node(fwnode), "msi-ranges",
					 0, &pcie->msi_base);
	if (ret)
		return ret;

	ret = of_property_read_u32_index(to_of_node(fwnode), "msi-ranges",
					 1, &pcie->nvecs);
	if (ret)
		return ret;

	pcie->bitmap = devm_bitmap_zalloc(pcie->dev, pcie->nvecs, GFP_KERNEL);
	if (!pcie->bitmap)
		return -ENOMEM;

	parent_intc = of_irq_find_parent(to_of_node(fwnode));
	parent = irq_find_host(parent_intc);
	if (!parent_intc || !parent) {
		dev_err(pcie->dev, "failed to find parent domain\n");
		return -ENXIO;
	}

	parent = irq_domain_create_hierarchy(parent, 0, pcie->nvecs, fwnode,
					     &apple_msi_domain_ops, pcie);
	if (!parent) {
		dev_err(pcie->dev, "failed to create IRQ domain\n");
		return -ENOMEM;
	}
	irq_domain_update_bus_token(parent, DOMAIN_BUS_NEXUS);

	pcie->domain = pci_msi_create_irq_domain(fwnode, &apple_msi_info,
						 parent);
	if (!pcie->domain) {
		dev_err(pcie->dev, "failed to create MSI domain\n");
		irq_domain_remove(parent);
		return -ENOMEM;
	}

	return 0;
}

#define set32(addr, value) rmwl(0, value, addr)
#define clear32(addr, value) rmwl(value, 0, addr)
#define poll32(addr, mask, value, timeout) \
	readl_relaxed_poll_timeout(addr, stat, \
				   (stat & (mask)) == (value), 100, 250000)

/* PHY registers */

#define APCIE_PHY_CTRL         0x000
#define APCIE_PHY_CTRL_CLK0REQ BIT(0)
#define APCIE_PHY_CTRL_CLK1REQ BIT(1)
#define APCIE_PHY_CTRL_CLK0ACK BIT(2)
#define APCIE_PHY_CTRL_CLK1ACK BIT(3)
#define APCIE_PHY_CTRL_RESET   BIT(7)

/* Port registers */

#define APCIE_PORT_APPCLK    0x800
#define APCIE_PORT_APPCLK_EN BIT(0)

#define APCIE_PORT_STATUS     0x804
#define APCIE_PORT_STATUS_RUN BIT(0)

#define APCIE_PORT_RESET     0x814
#define APCIE_PORT_RESET_DIS BIT(0)

/* DesignWare PCIe Core registers */

#define DWC_DBI_RO_WR    0x8bc
#define DWC_DBI_RO_WR_EN BIT(0)

static int apple_m1_pci_preinit(void __iomem *phy_base,
				void __iomem *rc_base,
				void __iomem *config_base,
				void __iomem *port_base[3])
{
	u32 stat;
	set32(phy_base + APCIE_PHY_CTRL, APCIE_PHY_CTRL_CLK0REQ);
	if (poll32(phy_base + APCIE_PHY_CTRL, APCIE_PHY_CTRL_CLK0ACK, APCIE_PHY_CTRL_CLK0ACK, 50000)) {
		printk("pcie: Timeout enabling PHY CLK0\n");
		return -EINVAL;
	}

	set32(phy_base + APCIE_PHY_CTRL, APCIE_PHY_CTRL_CLK1REQ);
	if (poll32(phy_base + APCIE_PHY_CTRL, APCIE_PHY_CTRL_CLK1ACK, APCIE_PHY_CTRL_CLK1ACK, 50000)) {
		printk("pcie: Timeout enabling PHY CLK1\n");
		return -EINVAL;
	}

	clear32(phy_base + APCIE_PHY_CTRL, APCIE_PHY_CTRL_RESET);
	udelay(1);

	/* ??? */
	set32(rc_base + 0x24, 1);
	udelay(1);

	int port;
	for (port = 0; port < 3; port++) {
		char bridge[64];

		/*
		 * Initialize RC port.
		 */
		set32(port_base[port] + APCIE_PORT_APPCLK, APCIE_PORT_APPCLK_EN);

		/* PERSTN */
		set32(port_base[port] + APCIE_PORT_RESET, APCIE_PORT_RESET_DIS);

		if (poll32(port_base[port] + APCIE_PORT_STATUS, APCIE_PORT_STATUS_RUN,
			   APCIE_PORT_STATUS_RUN, 250000))
			return -EINVAL;

		/* Make Designware PCIe Core registers writable. */
		set32(config_base + DWC_DBI_RO_WR, DWC_DBI_RO_WR_EN);

		/* Make Designware PCIe Core registers readonly. */
		clear32(config_base + DWC_DBI_RO_WR, DWC_DBI_RO_WR_EN);

		/* Move to the next PCIe device on this bus. */
		config_base += (1 << 15);
	}

	return 0;
}


static int apple_m1_pci_init(struct pci_config_window *cfg)
{
	struct device *dev = cfg->parent;
	struct platform_device *platform = to_platform_device(dev);

	struct apple_pcie *pcie;
	struct device_node *of_port;
	int ret, i;
	static int count = 0;
	void __iomem *port_base[3] = { 0, };

	if (count++ < 10)
		return -ENODEV;

	pcie = devm_kzalloc(dev, sizeof(*pcie), GFP_KERNEL);
	if (!pcie)
		return -ENOMEM;

	pcie->dev = dev;

	mutex_init(&pcie->lock);

	pcie->rc = devm_platform_ioremap_resource(platform, 1);

	if (IS_ERR(pcie->rc))
		return -ENODEV;

	if (1) {
		void __iomem *phy_base;
		void __iomem *rc_base;
		void __iomem *config_base;

		phy_base = pcie->rc + 0x80000;
		rc_base = pcie->rc;
		config_base = cfg->win;
		port_base[0] = devm_platform_ioremap_resource(platform, 2);
		port_base[1] = devm_platform_ioremap_resource(platform, 3);
		port_base[2] = devm_platform_ioremap_resource(platform, 4);

		printk("base addrs: %p %p %p %p %p %p\n",
		       phy_base, rc_base, config_base, port_base[0],
		       port_base[1], port_base[2]);
		apple_m1_pci_preinit(phy_base, rc_base, config_base,
				     port_base);
	}

	i = 0;

	for_each_child_of_node(dev->of_node, of_port) {
		struct gpio_desc *reset;

		reset = gpiod_get_from_of_node(of_port, "reset-gpios", 0,
					       GPIOD_OUT_LOW, "#PERST");
		if (IS_ERR(reset))
			return PTR_ERR(reset);

		ret = apple_pcie_setup_port(pcie, reset, i,
					    port_base[i]);

		gpiod_put(reset);
		if (ret) {
			dev_err(pcie->dev, "Port %u setup fail: %d\n", i, ret);
			return ret;
		}

		++i;
	}

	return apple_msi_init(pcie);
}

static const struct pci_ecam_ops apple_m1_cfg_ecam_ops = {
	.init		= apple_m1_pci_init,
	.pci_ops	= {
		.map_bus	= pci_ecam_map_bus,
		.read		= pci_generic_config_read,
		.write		= pci_generic_config_write,
	}
};

static const struct of_device_id apple_pci_of_match[] = {
	{ .compatible = "apple,pcie", .data = &apple_m1_cfg_ecam_ops },
	{ }
};
MODULE_DEVICE_TABLE(of, apple_pci_of_match);

static struct platform_driver apple_pci_driver = {
	.driver = {
		.name = "pcie-apple",
		.of_match_table = apple_pci_of_match,
	},
	.probe = pci_host_common_probe,
	.remove = pci_host_common_remove,
};
module_platform_driver(apple_pci_driver);

MODULE_LICENSE("GPL v2");
