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
 * This driver handles FIQs. These are used for Fast IPIs (TODO), the
 * ARMv8 timer IRQs, and performance counters (TODO).
 *
 * Implementation notes:
 *
 * - This driver creates one IRQ domain, for FIQs.
 * - DT bindings use 3-cell form (like GIC):
 *   - <1 nr flags> - FIQ #nr
 *     - nr=0  Physical HV timer
 *     - nr=1  Virtual HV timer
 *     - nr=2  Physical guest timer
 *     - nr=3  Virtual guest timer
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/bits.h>
#include <linux/bitfield.h>
#include <linux/cpuhotplug.h>
#include <linux/io.h>
#include <linux/irqchip.h>
#include <linux/irqdomain.h>
#include <linux/limits.h>
#include <linux/of_address.h>
#include <linux/slab.h>
#include <asm/exception.h>
#include <asm/sysreg.h>
#include <asm/virt.h>

#include <dt-bindings/interrupt-controller/apple-aic.h>

/*
 * IMP-DEF sysregs that control FIQ sources
 * Note: sysreg-based IPIs are not supported yet.
 */

/* Core PMC control register */
#define SYS_IMP_APL_PMCR0_EL1		sys_reg(3, 1, 15, 0, 0)
#define PMCR0_IMODE			GENMASK(10, 8)
#define PMCR0_IMODE_OFF			0
#define PMCR0_IMODE_PMI			1
#define PMCR0_IMODE_AIC			2
#define PMCR0_IMODE_HALT		3
#define PMCR0_IMODE_FIQ			4
#define PMCR0_IACT			BIT(11)

/* IPI request registers */
#define SYS_IMP_APL_IPI_RR_LOCAL_EL1	sys_reg(3, 5, 15, 0, 0)
#define SYS_IMP_APL_IPI_RR_GLOBAL_EL1	sys_reg(3, 5, 15, 0, 1)
#define IPI_RR_CPU			GENMASK(7, 0)
/* Cluster only used for the GLOBAL register */
#define IPI_RR_CLUSTER			GENMASK(23, 16)
#define IPI_RR_TYPE			GENMASK(29, 28)
#define IPI_RR_IMMEDIATE		0
#define IPI_RR_RETRACT			1
#define IPI_RR_DEFERRED			2
#define IPI_RR_NOWAKE			3

/* IPI status register */
#define SYS_IMP_APL_IPI_SR_EL1		sys_reg(3, 5, 15, 1, 1)
#define IPI_SR_PENDING			BIT(0)

/* Guest timer FIQ enable register */
#define SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2	sys_reg(3, 5, 15, 1, 3)
#define VM_TMR_FIQ_ENABLE_V		BIT(0)
#define VM_TMR_FIQ_ENABLE_P		BIT(1)

/* Deferred IPI countdown register */
#define SYS_IMP_APL_IPI_CR_EL1		sys_reg(3, 5, 15, 3, 1)

/* Uncore PMC control register */
#define SYS_IMP_APL_UPMCR0_EL1		sys_reg(3, 7, 15, 0, 4)
#define UPMCR0_IMODE			GENMASK(18, 16)
#define UPMCR0_IMODE_OFF		0
#define UPMCR0_IMODE_AIC		2
#define UPMCR0_IMODE_HALT		3
#define UPMCR0_IMODE_FIQ		4

/* Uncore PMC status register */
#define SYS_IMP_APL_UPMSR_EL1		sys_reg(3, 7, 15, 6, 4)
#define UPMSR_IACT			BIT(0)

#define NR_FIQ			4
#define FIQ_NR_IPI		1

/*
 * FIQ hwirq index definitions: FIQ sources use the DT binding defines
 * directly, except that timers are special. At the irqchip level, the
 * two timer types are represented by their access method: _EL0 registers
 * or _EL02 registers. In the DT binding, the timers are represented
 * by their purpose (HV or guest). This mapping is for when the kernel is
 * running at EL2 (with VHE). When the kernel is running at EL1, the
 * mapping differs and irq_domain_translate() performs the remapping.
 */

#define FIQ_TMR_HV_PHYS AIC_TMR_HV_PHYS
#define FIQ_TMR_HV_VIRT AIC_TMR_HV_VIRT
#define FIQ_TMR_GUEST_PHYS AIC_TMR_GUEST_PHYS
#define FIQ_TMR_GUEST_VIRT AIC_TMR_GUEST_VIRT

#define FIQ_TMR_EL0_PHYS	FIQ_TMR_HV_PHYS
#define FIQ_TMR_EL0_VIRT	FIQ_TMR_HV_VIRT
#define FIQ_TMR_EL02_PHYS	FIQ_TMR_GUEST_PHYS
#define FIQ_TMR_EL02_VIRT	FIQ_TMR_GUEST_VIRT

#define FIQ_IPI		4
#define FIQ_OTHER	5

struct fiq_irq_chip {
	struct irq_domain *domain;
	struct irq_domain *ipi_domain;
};

static DEFINE_PER_CPU(uint32_t, fiq_unmasked);

static struct fiq_irq_chip *fiq_irqc;

/*
 * FIQ irqchip
 */

static void fiq_set_mask(struct irq_data *d)
{
	/* Only the guest timers have real mask bits, unfortunately. */
	switch (irqd_to_hwirq(d)) {
	case FIQ_TMR_EL02_PHYS:
		sysreg_clear_set_s(SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2, VM_TMR_FIQ_ENABLE_P, 0);
		isb();
		break;
	case FIQ_TMR_EL02_VIRT:
		sysreg_clear_set_s(SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2, VM_TMR_FIQ_ENABLE_V, 0);
		isb();
		break;
	default:
		break;
	}
}

static void fiq_clear_mask(struct irq_data *d)
{
	switch (irqd_to_hwirq(d)) {
	case FIQ_TMR_EL02_PHYS:
		sysreg_clear_set_s(SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2, 0, VM_TMR_FIQ_ENABLE_P);
		isb();
		break;
	case FIQ_TMR_EL02_VIRT:
		sysreg_clear_set_s(SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2, 0, VM_TMR_FIQ_ENABLE_V);
		isb();
		break;
	default:
		break;
	}
}

static void fiq_mask(struct irq_data *d)
{
	fiq_set_mask(d);
	__this_cpu_and(fiq_unmasked, ~BIT(irqd_to_hwirq(d)));
}

static void fiq_unmask(struct irq_data *d)
{
	fiq_clear_mask(d);
	__this_cpu_or(fiq_unmasked, BIT(irqd_to_hwirq(d)));
}

static void fiq_eoi(struct irq_data *d)
{
	/* We mask to ack (where we can), so we need to unmask at EOI. */
	if (__this_cpu_read(fiq_unmasked) & BIT(irqd_to_hwirq(d)))
		fiq_clear_mask(d);
}

#define TIMER_FIRING(x)						\
	(((x) & (ARCH_TIMER_CTRL_ENABLE | ARCH_TIMER_CTRL_IT_MASK |	\
		 ARCH_TIMER_CTRL_IT_STAT)) ==				\
	 (ARCH_TIMER_CTRL_ENABLE | ARCH_TIMER_CTRL_IT_STAT))

void __exception_irq_entry handle_fiq(struct pt_regs *regs)
{
	struct fiq_irq_chip *ic = fiq_irqc;
	/*
	 * It would be really nice if we had a system register that lets us get
	 * the FIQ source state without having to peek down into sources...
	 * but such a register does not seem to exist.
	 *
	 * So, we have these potential sources to test for:
	 *  - Fast IPIs (not yet used)
	 *  - The 4 timers (CNTP, CNTV for each of HV and guest)
	 *  - Per-core PMCs (not yet supported)
	 *  - Per-cluster uncore PMCs (not yet supported)
	 *
	 * Since not dealing with any of these results in a FIQ storm,
	 * we check for everything here, even things we don't support yet.
	 */

	if (read_sysreg_s(SYS_IMP_APL_IPI_SR_EL1) & IPI_SR_PENDING) {
		pr_err_ratelimited("Fast IPI fired. Acking.\n");
		write_sysreg_s(IPI_SR_PENDING, SYS_IMP_APL_IPI_SR_EL1);
	} else if (TIMER_FIRING(read_sysreg(cntp_ctl_el0))) {
		handle_domain_irq(ic->domain, FIQ_TMR_EL0_PHYS, regs);
	} else if (TIMER_FIRING(read_sysreg(cntv_ctl_el0))) {
		handle_domain_irq(ic->domain, FIQ_TMR_EL0_VIRT, regs);
	} else if (is_kernel_in_hyp_mode()) {
		uint64_t enabled = read_sysreg_s(SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2);

		if ((enabled & VM_TMR_FIQ_ENABLE_P) &&
		    TIMER_FIRING(read_sysreg_s(SYS_CNTP_CTL_EL02)))
			handle_domain_irq(ic->domain, FIQ_TMR_EL02_PHYS, regs);

		if ((enabled & VM_TMR_FIQ_ENABLE_V) &&
		    TIMER_FIRING(read_sysreg_s(SYS_CNTV_CTL_EL02)))
			handle_domain_irq(fiq_irqc->domain, FIQ_TMR_EL02_VIRT, regs);
	} else if ((read_sysreg_s(SYS_IMP_APL_PMCR0_EL1) & (PMCR0_IMODE | PMCR0_IACT)) ==
			(FIELD_PREP(PMCR0_IMODE, PMCR0_IMODE_FIQ) | PMCR0_IACT)) {
		/*
		 * Not supported yet, let's figure out how to handle this when
		 * we implement these proprietary performance counters. For now,
		 * just mask it and move on.
		 */
		pr_err_ratelimited("PMC FIQ fired. Masking.\n");
		sysreg_clear_set_s(SYS_IMP_APL_PMCR0_EL1, PMCR0_IMODE | PMCR0_IACT,
				   FIELD_PREP(PMCR0_IMODE, PMCR0_IMODE_OFF));
	} else if (FIELD_GET(UPMCR0_IMODE, read_sysreg_s(SYS_IMP_APL_UPMCR0_EL1)) == UPMCR0_IMODE_FIQ &&
			(read_sysreg_s(SYS_IMP_APL_UPMSR_EL1) & UPMSR_IACT)) {
		/* Same story with uncore PMCs */
		pr_err_ratelimited("Uncore PMC FIQ fired. Masking.\n");
		sysreg_clear_set_s(SYS_IMP_APL_UPMCR0_EL1, UPMCR0_IMODE,
				   FIELD_PREP(UPMCR0_IMODE, UPMCR0_IMODE_OFF));
	}
}

static int fiq_set_type(struct irq_data *d, unsigned int type)
{
	return (type == IRQ_TYPE_LEVEL_HIGH) ? 0 : -EINVAL;
}

static struct irq_chip fiq_chip = {
	.name = "FIQ",
	.irq_mask = fiq_mask,
	.irq_unmask = fiq_unmask,
	.irq_ack = fiq_set_mask,
	.irq_eoi = fiq_eoi,
	.irq_set_type = fiq_set_type,
};

/*
 * Main IRQ domain
 */

static int irq_domain_map(struct irq_domain *id, unsigned int irq,
			      irq_hw_number_t hw)
{
	irq_set_percpu_devid(irq);
	irq_domain_set_info(id, irq, hw, &fiq_chip, id->host_data,
			    handle_percpu_devid_irq, NULL, NULL);

	return 0;
}

static int irq_domain_translate(struct irq_domain *id,
				    struct irq_fwspec *fwspec,
				    unsigned long *hwirq,
				    unsigned int *type)
{
	if (fwspec->param_count != 3 || !is_of_node(fwspec->fwnode))
		return -EINVAL;

	switch (fwspec->param[0]) {
	case AIC_FIQ:
		if (fwspec->param[1] >= NR_FIQ)
			return -EINVAL;
		*hwirq = fwspec->param[1];

		/*
		 * In EL1 the non-redirected registers are the guest's,
		 * not EL2's, so remap the hwirqs to match.
		 */
		if (!is_kernel_in_hyp_mode()) {
			switch (fwspec->param[1]) {
			case FIQ_TMR_GUEST_PHYS:
				*hwirq = FIQ_TMR_EL0_PHYS;
				break;
			case FIQ_TMR_GUEST_VIRT:
				*hwirq = FIQ_TMR_EL0_VIRT;
				break;
			case FIQ_TMR_HV_PHYS:
			case FIQ_TMR_HV_VIRT:
				return -ENOENT;
			default:
				break;
			}
		}
		break;
	default:
		return -EINVAL;
	}

	*type = fwspec->param[2] & IRQ_TYPE_SENSE_MASK;

	return 0;
}

static int irq_domain_alloc(struct irq_domain *domain, unsigned int virq,
			    unsigned int nr_irqs, void *arg)
{
	unsigned int type = IRQ_TYPE_NONE;
	struct irq_fwspec *fwspec = arg;
	irq_hw_number_t hwirq;
	int i, ret;

	ret = irq_domain_translate(domain, fwspec, &hwirq, &type);
	if (ret)
		return ret;

	for (i = 0; i < nr_irqs; i++) {
		ret = irq_domain_map(domain, virq + i, hwirq + i);
		if (ret)
			return ret;
	}

	return 0;
}

static void irq_domain_free(struct irq_domain *domain, unsigned int virq,
			    unsigned int nr_irqs)
{
	int i;

	for (i = 0; i < nr_irqs; i++) {
		struct irq_data *d = irq_domain_get_irq_data(domain, virq + i);

		irq_set_handler(virq + i, NULL);
		irq_domain_reset_irq_data(d);
	}
}

static const struct irq_domain_ops irq_domain_ops = {
	.translate	= irq_domain_translate,
	.alloc		= irq_domain_alloc,
	.free		= irq_domain_free,
};

static const struct irq_domain_ops ipi_domain_ops = {
	.alloc		= irq_domain_alloc,
	.free		= irq_domain_free,
};

int fiq_init_cpu(unsigned int cpu)
{
	/* Mask all hard-wired per-CPU FIQ sources */

	/* Pending Fast IPI FIQs */
	write_sysreg_s(IPI_SR_PENDING, SYS_IMP_APL_IPI_SR_EL1);

	/* Timer FIQs */
	sysreg_clear_set(cntp_ctl_el0, 0, ARCH_TIMER_CTRL_IT_MASK);
	sysreg_clear_set(cntv_ctl_el0, 0, ARCH_TIMER_CTRL_IT_MASK);

	/* EL2-only (VHE mode) IRQ sources */
	if (is_kernel_in_hyp_mode()) {
		/* Guest timers */
		sysreg_clear_set_s(SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2,
				   VM_TMR_FIQ_ENABLE_V | VM_TMR_FIQ_ENABLE_P, 0);
	}

	/* PMC FIQ */
	sysreg_clear_set_s(SYS_IMP_APL_PMCR0_EL1, PMCR0_IMODE | PMCR0_IACT,
			   FIELD_PREP(PMCR0_IMODE, PMCR0_IMODE_OFF));

	/* Uncore PMC FIQ */
	sysreg_clear_set_s(SYS_IMP_APL_UPMCR0_EL1, UPMCR0_IMODE,
			   FIELD_PREP(UPMCR0_IMODE, UPMCR0_IMODE_OFF));

	/* Commit all of the above */
	isb();

	/* Initialize the local mask state */
	__this_cpu_write(fiq_unmasked, 0);

	return 0;
}

/* Regular old IRQ handler for "other" FIQs. This will have to go away
 * and forward the PMC FIQs at some point, but for now it's better to
 * have the stats that we get from a regular IRQ handler. */

static enum irqreturn fiq_handler(int irq, void *ptr)
{
	if ((read_sysreg_s(SYS_IMP_APL_PMCR0_EL1) & (PMCR0_IMODE | PMCR0_IACT)) ==
			(FIELD_PREP(PMCR0_IMODE, PMCR0_IMODE_FIQ) | PMCR0_IACT)) {
		/*
		 * Not supported yet, let's figure out how to handle this when
		 * we implement these proprietary performance counters. For now,
		 * just mask it and move on.
		 */
		pr_err_ratelimited("PMC FIQ fired. Masking.\n");
		sysreg_clear_set_s(SYS_IMP_APL_PMCR0_EL1, PMCR0_IMODE | PMCR0_IACT,
				   FIELD_PREP(PMCR0_IMODE, PMCR0_IMODE_OFF));
		return IRQ_HANDLED;
	} else if (FIELD_GET(UPMCR0_IMODE, read_sysreg_s(SYS_IMP_APL_UPMCR0_EL1)) == UPMCR0_IMODE_FIQ &&
			(read_sysreg_s(SYS_IMP_APL_UPMSR_EL1) & UPMSR_IACT)) {
		/* Same story with uncore PMCs */
		pr_err_ratelimited("Uncore PMC FIQ fired. Masking.\n");
		sysreg_clear_set_s(SYS_IMP_APL_UPMCR0_EL1, UPMCR0_IMODE,
				   FIELD_PREP(UPMCR0_IMODE, UPMCR0_IMODE_OFF));
		return IRQ_HANDLED;
	}

	return IRQ_NONE;
}

static int __init fiq_of_ic_init(struct device_node *node, struct device_node *parent)
{
	struct fiq_irq_chip *ic;
	unsigned int fiq_other;
	int base_ipi;
	bool use_for_ipi = of_property_read_bool(node, "use-for-ipi");

	ic = kzalloc(sizeof(*ic), GFP_KERNEL);
	if (!ic)
		return -ENOMEM;

	fiq_irqc = ic;

	ic->domain = irq_domain_create_linear(of_node_to_fwnode(node),
					      NR_FIQ, &irq_domain_ops, ic);
	if (WARN_ON(!ic->domain)) {
		kfree(ic);
		return -ENODEV;
	}

	if (of_property_read_bool(node, "use-for-ipi"))
		ic->ipi_domain = irq_domain_create_linear
			(of_node_to_fwnode(node), FIQ_NR_IPI,
			 &ipi_domain_ops, ic);
	if (ic->ipi_domain) {
		ic->ipi_domain->flags |= IRQ_DOMAIN_FLAG_IPI_SINGLE;

		base_ipi = __irq_domain_alloc_irqs(ic->ipi_domain, -1, FIQ_NR_IPI,
						   NUMA_NO_NODE, NULL, false, NULL);

		if (base_ipi) {
			set_smp_ipi_range(base_ipi, FIQ_NR_IPI);
		}
	}

	set_handle_fiq(handle_fiq);

	if (!is_kernel_in_hyp_mode())
		pr_info("Kernel running in EL1, mapping interrupts");

	cpuhp_setup_state(CPUHP_AP_IRQ_APPLE_FIQ_STARTING,
			  "irqchip/apple-fiq/fiq:starting",
			  fiq_init_cpu, NULL);

	if (__irq_resolve_mapping(ic->domain, FIQ_OTHER, &fiq_other))
		WARN_ON(request_irq(fiq_other, fiq_handler, IRQF_SHARED,
				    "PMC FIQ handler", ic) < 0);

	pr_info("Initialized with %d FIQs, %sused for IPI\n", NR_FIQ,
		use_for_ipi ? "" : "not ");;

	return 0;
}

IRQCHIP_DECLARE(apple_m1_fiq, "apple,fiq", fiq_of_ic_init);
