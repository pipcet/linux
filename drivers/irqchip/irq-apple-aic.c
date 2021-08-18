// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright The Asahi Linux Contributors
 *
 * Based on irq-lpc32xx:
 *   Copyright 2015-2016 Vladimir Zapolskiy <vz@mleia.com>
 * Based on irq-bcm2836:
 *   Copyright 2015 Broadcom
 */

/*
 * AIC is a fairly simple interrupt controller with the following features:
 *
 * - 896 level-triggered hardware IRQs
 *   - Single mask bit per IRQ
 *   - Per-IRQ affinity setting
 *   - Automatic masking on event delivery (auto-ack)
 *   - Software triggering (ORed with hw line)
 * - 2 per-CPU IPIs (meant as "self" and "other", but they are
 *   interchangeable if not symmetric)
 * - Automatic prioritization (single event/ack register per CPU, lower IRQs =
 *   higher priority)
 * - Automatic masking on ack
 * - Default "this CPU" register view and explicit per-CPU views
 *
 * Implementation notes:
 *
 * - This driver creates two IRQ domains, one for HW IRQs, and one for
 *   the single IPI we actually support.
 * - Since Linux needs more than 2 IPIs, we rely on the arch IRQ layer
 *   to funnel IPIs through its own implementation, using just one
 *   per-CPU real IPI (the second "self" IPI is unused).
 * - DT bindings use 3-cell form (like GIC):
 *   - <0 nr flags> - hwirq #nr
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/bits.h>
#include <linux/bitfield.h>
#include <linux/cpuhotplug.h>
#include <linux/io.h>
#include <linux/irqchip.h>
#include <linux/irqchip/arm-vgic-info.h>
#include <linux/irqdomain.h>
#include <linux/limits.h>
#include <linux/of_address.h>
#include <linux/slab.h>
#include <asm/exception.h>
#include <asm/sysreg.h>
#include <asm/virt.h>

#include <dt-bindings/interrupt-controller/apple-aic.h>

/*
 * AIC registers (MMIO)
 */

#define AIC_INFO		0x0004
#define AIC_INFO_NR_HW		GENMASK(15, 0)

#define AIC_CONFIG		0x0010

#define AIC_WHOAMI		0x2000
#define AIC_EVENT		0x2004
#define AIC_EVENT_TYPE		GENMASK(31, 16)
#define AIC_EVENT_NUM		GENMASK(15, 0)

#define AIC_EVENT_TYPE_HW	1
#define AIC_EVENT_TYPE_IPI	4
#define AIC_EVENT_IPI_OTHER	1
#define AIC_EVENT_IPI_SELF	2

#define AIC_IPI_SEND		0x2008
#define AIC_IPI_ACK		0x200c
#define AIC_IPI_MASK_SET	0x2024
#define AIC_IPI_MASK_CLR	0x2028

#define AIC_IPI_SEND_CPU(cpu)	BIT(cpu)

#define AIC_IPI_OTHER		BIT(0)
#define AIC_IPI_SELF		BIT(31)

#define AIC_TARGET_CPU		0x3000
#define AIC_SW_SET		0x4000
#define AIC_SW_CLR		0x4080
#define AIC_MASK_SET		0x4100
#define AIC_MASK_CLR		0x4180

#define AIC_CPU_IPI_SET(cpu)	(0x5008 + ((cpu) << 7))
#define AIC_CPU_IPI_CLR(cpu)	(0x500c + ((cpu) << 7))
#define AIC_CPU_IPI_MASK_SET(cpu) (0x5024 + ((cpu) << 7))
#define AIC_CPU_IPI_MASK_CLR(cpu) (0x5028 + ((cpu) << 7))

#define MASK_REG(x)		(4 * ((x) >> 5))
#define MASK_BIT(x)		BIT((x) & GENMASK(4, 0))

struct aic_irq_chip {
	void __iomem *base;
	struct irq_domain *hw_domain;
	struct irq_domain *ipi_domain;
	int nr_hw;
};

#define AIC_NR_IPI 1

static struct aic_irq_chip *aic_irqc;

static void aic_handle_ipi(int index, struct pt_regs *regs);

static u32 aic_ic_read(struct aic_irq_chip *ic, u32 reg)
{
	return readl_relaxed(ic->base + reg);
}

static void aic_ic_write(struct aic_irq_chip *ic, u32 reg, u32 val)
{
	writel_relaxed(val, ic->base + reg);
}

/*
 * IRQ irqchip
 */

static void aic_irq_mask(struct irq_data *d)
{
	struct aic_irq_chip *ic = irq_data_get_irq_chip_data(d);

	aic_ic_write(ic, AIC_MASK_SET + MASK_REG(irqd_to_hwirq(d)),
		     MASK_BIT(irqd_to_hwirq(d)));
}

static void aic_irq_unmask(struct irq_data *d)
{
	struct aic_irq_chip *ic = irq_data_get_irq_chip_data(d);

	aic_ic_write(ic, AIC_MASK_CLR + MASK_REG(irqd_to_hwirq(d)),
		     MASK_BIT(irqd_to_hwirq(d)));
}

static void aic_irq_eoi(struct irq_data *d)
{
	/*
	 * Reading the interrupt reason automatically acknowledges and masks
	 * the IRQ, so we just unmask it here if needed.
	 */
	if (!irqd_irq_masked(d))
		aic_irq_unmask(d);
}

static void __exception_irq_entry aic_handle_irq(struct pt_regs *regs)
{
	struct aic_irq_chip *ic = aic_irqc;
	u32 event, type, irq;

	do {
		/*
		 * We cannot use a relaxed read here, as reads from DMA buffers
		 * need to be ordered after the IRQ fires.
		 */
		event = readl(ic->base + AIC_EVENT);
		type = FIELD_GET(AIC_EVENT_TYPE, event);
		irq = FIELD_GET(AIC_EVENT_NUM, event);

		if (type == AIC_EVENT_TYPE_HW)
			handle_domain_irq(ic->hw_domain, irq, regs);
		else if (type == AIC_EVENT_TYPE_IPI)
			aic_handle_ipi(0 /* irq */, regs);
		else if (event != 0)
			pr_err_ratelimited("Unknown IRQ event %d, %d\n", type, irq);
	} while (event);

	/*
	 * vGIC maintenance interrupts end up here too, so we need to check
	 * for them separately. This should never trigger if KVM is working
	 * properly, because it will have already taken care of clearing it
	 * on guest exit before this handler runs.
	 *
	 * XXX it would be nice to skip this check.
	 */
	if (is_kernel_in_hyp_mode() && (read_sysreg_s(SYS_ICH_HCR_EL2) & ICH_HCR_EN) &&
		read_sysreg_s(SYS_ICH_MISR_EL2) != 0) {
		pr_err_ratelimited("vGIC IRQ fired and not handled by KVM, disabling.\n");
		sysreg_clear_set_s(SYS_ICH_HCR_EL2, ICH_HCR_EN, 0);
	}
}

static int aic_irq_set_affinity(struct irq_data *d,
				const struct cpumask *mask_val, bool force)
{
	irq_hw_number_t hwirq = irqd_to_hwirq(d);
	struct aic_irq_chip *ic = irq_data_get_irq_chip_data(d);
	int cpu;
	u32 mask = 0;

	for_each_cpu(cpu, mask_val)
		mask |= BIT(cpu);

	aic_ic_write(ic, AIC_TARGET_CPU + hwirq * 4, mask);
	irq_data_update_effective_affinity(d, mask_val);

	return IRQ_SET_MASK_OK;
}

static int aic_irq_set_type(struct irq_data *d, unsigned int type)
{
	/*
	 * Some IRQs (e.g. MSIs) implicitly have edge semantics, and we don't
	 * have a way to find out the type of any given IRQ, so just allow both.
	 */
	return (type == IRQ_TYPE_LEVEL_HIGH || type == IRQ_TYPE_EDGE_RISING) ? 0 : -EINVAL;
}

static struct irq_chip aic_chip = {
	.name = "AIC",
	.irq_mask = aic_irq_mask,
	.irq_unmask = aic_irq_unmask,
	.irq_eoi = aic_irq_eoi,
	.irq_set_affinity = aic_irq_set_affinity,
	.irq_set_type = aic_irq_set_type,
};

/*
 * Main IRQ domain
 */

static int aic_irq_domain_map(struct irq_domain *id, unsigned int irq,
			      irq_hw_number_t hw)
{
	irq_domain_set_info(id, irq, hw, &aic_chip, id->host_data,
			    handle_fasteoi_irq, NULL, NULL);
	irqd_set_single_target(irq_desc_get_irq_data(irq_to_desc(irq)));

	return 0;
}

static int aic_irq_domain_translate(struct irq_domain *id,
				    struct irq_fwspec *fwspec,
				    unsigned long *hwirq,
				    unsigned int *type)
{
	struct aic_irq_chip *ic = id->host_data;

	if (fwspec->param_count != 3 || !is_of_node(fwspec->fwnode))
		return -EINVAL;

	switch (fwspec->param[0]) {
	case AIC_IRQ:
		if (fwspec->param[1] >= ic->nr_hw)
			return -EINVAL;
		*hwirq = fwspec->param[1];
		break;
	default:
		return -EINVAL;
	}

	*type = fwspec->param[2] & IRQ_TYPE_SENSE_MASK;

	return 0;
}

static int aic_irq_domain_alloc(struct irq_domain *domain, unsigned int virq,
				unsigned int nr_irqs, void *arg)
{
	unsigned int type = IRQ_TYPE_NONE;
	struct irq_fwspec *fwspec = arg;
	irq_hw_number_t hwirq;
	int i, ret;

	ret = aic_irq_domain_translate(domain, fwspec, &hwirq, &type);
	if (ret)
		return ret;

	for (i = 0; i < nr_irqs; i++) {
		ret = aic_irq_domain_map(domain, virq + i, hwirq + i);
		if (ret)
			return ret;
	}

	return 0;
}

static void aic_irq_domain_free(struct irq_domain *domain, unsigned int virq,
				unsigned int nr_irqs)
{
	int i;

	for (i = 0; i < nr_irqs; i++) {
		struct irq_data *d = irq_domain_get_irq_data(domain, virq + i);

		irq_set_handler(virq + i, NULL);
		irq_domain_reset_irq_data(d);
	}
}

static const struct irq_domain_ops aic_irq_domain_ops = {
	.translate	= aic_irq_domain_translate,
	.alloc		= aic_irq_domain_alloc,
	.free		= aic_irq_domain_free,
};

/*
 * IPI irqchip
 */

static int aic_ipi_number(struct irq_data *d)
{
	return irqd_to_hwirq(d) ? AIC_IPI_OTHER : AIC_IPI_OTHER;
}

static void aic_ipi_mask(struct irq_data *d)
{
	aic_ic_write(aic_irqc, AIC_IPI_MASK_SET, aic_ipi_number(d));
}

static void aic_ipi_unmask(struct irq_data *d)
{
	aic_ic_write(aic_irqc, AIC_IPI_MASK_CLR, aic_ipi_number(d));
}

static void aic_ipi_send_mask(struct irq_data *d, const struct cpumask *mask)
{
	struct aic_irq_chip *ic = irq_data_get_irq_chip_data(d);
	u32 send = 0;
	int cpu;

	for_each_cpu(cpu, mask)
		send |= AIC_IPI_SEND_CPU(cpu);

	if (send)
		aic_ic_write(ic, AIC_IPI_SEND, send);
}

static struct irq_chip ipi_chip = {
	.name = "AIC-IPI",
	.irq_mask = aic_ipi_mask,
	.irq_unmask = aic_ipi_unmask,
	.ipi_send_mask = aic_ipi_send_mask,
};

/*
 * IPI IRQ domain
 */

static void aic_handle_ipi(int index, struct pt_regs *regs)
{
	struct irq_domain *domain = aic_irqc->ipi_domain;
	struct aic_irq_chip *ic = aic_irqc;
	/*
	 * Ack the IPI. We need to order this after the AIC event read, but
	 * that is enforced by normal MMIO ordering guarantees.
	 */
	aic_ic_write(ic, AIC_IPI_ACK,
		     aic_ipi_number(irq_domain_get_irq_data(domain, index)));

	handle_domain_irq(domain, index, regs);

	/*
	 * No ordering needed here; at worst this just changes the timing of
	 * when the next IPI will be delivered.
	 */
	aic_ic_write(ic, AIC_IPI_MASK_CLR, AIC_IPI_OTHER);
}

static int aic_ipi_alloc(struct irq_domain *d, unsigned int virq,
			 unsigned int nr_irqs, void *args)
{
	int i;

	for (i = 0; i < nr_irqs; i++) {
		irq_set_percpu_devid(virq + i);
		irq_domain_set_info(d, virq + i, i, &ipi_chip, d->host_data,
				    handle_percpu_devid_irq, NULL, NULL);
	}

	return 0;
}

static void aic_ipi_free(struct irq_domain *d, unsigned int virq, unsigned int nr_irqs)
{
	/* Not freeing IPIs */
}

static const struct irq_domain_ops aic_ipi_domain_ops = {
	.alloc = aic_ipi_alloc,
	.free = aic_ipi_free,
};

static int aic_init_smp(struct aic_irq_chip *irqc, struct device_node *node)
{
	struct irq_domain *ipi_domain;
	int base_ipi;

	ipi_domain = irq_domain_create_linear(irqc->hw_domain->fwnode, AIC_NR_IPI,
					      &aic_ipi_domain_ops, irqc);
	if (WARN_ON(!ipi_domain))
		return -ENODEV;

	ipi_domain->flags |= IRQ_DOMAIN_FLAG_IPI_SINGLE;
	irq_domain_update_bus_token(ipi_domain, DOMAIN_BUS_IPI);

	base_ipi = __irq_domain_alloc_irqs(ipi_domain, -1, AIC_NR_IPI,
					   NUMA_NO_NODE, NULL, false, NULL);

	if (WARN_ON(base_ipi < 0)) {
		irq_domain_remove(ipi_domain);
		return -ENODEV;
	}

	set_smp_ipi_range(base_ipi, AIC_NR_IPI);

	irqc->ipi_domain = ipi_domain;

	return 0;
}

static int aic_init_cpu(unsigned int cpu)
{
	/* Mask hard-wired per-CPU IRQ sources */

	/* EL2-only (VHE mode) IRQ sources */
	if (is_kernel_in_hyp_mode()) {
		/* vGIC maintenance IRQ */
		sysreg_clear_set_s(SYS_ICH_HCR_EL2, ICH_HCR_EN, 0);
	}

	/* Commit the above */
	isb();

	/*
	 * Make sure the kernel's idea of logical CPU order is the same as AIC's
	 * If we ever end up with a mismatch here, we will have to introduce
	 * a mapping table similar to what other irqchip drivers do.
	 */
	WARN_ON(aic_ic_read(aic_irqc, AIC_WHOAMI) != smp_processor_id());

	/*
	 * Always keep IPIs unmasked at the hardware level (except auto-masking
	 * by AIC during processing). We manage masks at the vIPI level.
	 */
	aic_ic_write(aic_irqc, AIC_IPI_ACK, AIC_IPI_SELF | AIC_IPI_OTHER);
	aic_ic_write(aic_irqc, AIC_IPI_MASK_SET, AIC_IPI_SELF);
	aic_ic_write(aic_irqc, AIC_IPI_MASK_CLR, AIC_IPI_OTHER);

	return 0;
}

static struct gic_kvm_info vgic_info __initdata = {
	.type			= GIC_V3,
	.no_maint_irq_mask	= true,
	.no_hw_deactivation	= true,
};

static int __init aic_of_ic_init(struct device_node *node, struct device_node *parent)
{
	int i;
	void __iomem *regs;
	u32 info;
	struct aic_irq_chip *irqc;
	bool use_for_ipi = of_property_read_bool(node, "use-for-ipi");

	regs = of_iomap(node, 0);
	if (WARN_ON(!regs))
		return -EIO;

	irqc = kzalloc(sizeof(*irqc), GFP_KERNEL);
	if (!irqc)
		return -ENOMEM;

	aic_irqc = irqc;
	irqc->base = regs;

	info = aic_ic_read(irqc, AIC_INFO);
	irqc->nr_hw = FIELD_GET(AIC_INFO_NR_HW, info);

	irqc->hw_domain = irq_domain_create_linear(of_node_to_fwnode(node),
						   irqc->nr_hw,
						   &aic_irq_domain_ops, irqc);
	if (WARN_ON(!irqc->hw_domain)) {
		iounmap(irqc->base);
		kfree(irqc);
		return -ENODEV;
	}

	irq_domain_update_bus_token(irqc->hw_domain, DOMAIN_BUS_WIRED);

	if (use_for_ipi && aic_init_smp(irqc, node)) {
		irq_domain_remove(irqc->hw_domain);
		iounmap(irqc->base);
		kfree(irqc);
		return -ENODEV;
	}

	set_handle_irq(aic_handle_irq);

	for (i = 0; i < BITS_TO_U32(irqc->nr_hw); i++)
		aic_ic_write(irqc, AIC_MASK_SET + i * 4, U32_MAX);
	for (i = 0; i < BITS_TO_U32(irqc->nr_hw); i++)
		aic_ic_write(irqc, AIC_SW_CLR + i * 4, U32_MAX);
	for (i = 0; i < irqc->nr_hw; i++)
		aic_ic_write(irqc, AIC_TARGET_CPU + i * 4, 1);

	cpuhp_setup_state(CPUHP_AP_IRQ_APPLE_AIC_STARTING,
			  "irqchip/apple-aic/ipi:starting",
			  aic_init_cpu, NULL);

	vgic_set_kvm_info(&vgic_info);

	pr_info("Initialized with %d IRQs, 1 IPI, %sused for IPI\n", irqc->nr_hw,
		use_for_ipi ? "" : "not ");

	return 0;
}

IRQCHIP_DECLARE(apple_m1_aic, "apple,aic", aic_of_ic_init);
