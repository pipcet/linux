// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright The Asahi Linux Contributors
 *
 * Based on irq-lpc32xx:
 *   Copyright 2015-2016 Vladimir Zapolskiy <vz@mleia.com>
 * Based on irq-bcm2836:
 *   Copyright 2015 Broadcom
 */

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

/*
 * IPI irqchip
 */

static void aic_ipi_mask(struct irq_data *d)
{
	u32 irq_bit = BIT(irqd_to_hwirq(d));

	/* No specific ordering requirements needed here. */
	atomic_andnot(irq_bit, this_cpu_ptr(&aic_vipi_enable));
}

static void aic_ipi_unmask(struct irq_data *d)
{
	struct aic_irq_chip *ic = irq_data_get_irq_chip_data(d);
	u32 irq_bit = BIT(irqd_to_hwirq(d));

	atomic_or(irq_bit, this_cpu_ptr(&aic_vipi_enable));

	/*
	 * The atomic_or() above must complete before the atomic_read()
	 * below to avoid racing aic_ipi_send_mask().
	 */
	smp_mb__after_atomic();

	/*
	 * If a pending vIPI was unmasked, raise a HW IPI to ourselves.
	 * No barriers needed here since this is a self-IPI.
	 */
	if (atomic_read(this_cpu_ptr(&aic_vipi_flag)) & irq_bit)
		aic_ic_write(ic, AIC_IPI_SEND, AIC_IPI_SEND_CPU(smp_processor_id()));
}

static void aic_ipi_send_mask(struct irq_data *d, const struct cpumask *mask)
{
	struct aic_irq_chip *ic = irq_data_get_irq_chip_data(d);
	u32 irq_bit = BIT(irqd_to_hwirq(d));
	u32 send = 0;
	int cpu;
	unsigned long pending;

	for_each_cpu(cpu, mask) {
		/*
		 * This sequence is the mirror of the one in aic_ipi_unmask();
		 * see the comment there. Additionally, release semantics
		 * ensure that the vIPI flag set is ordered after any shared
		 * memory accesses that precede it. This therefore also pairs
		 * with the atomic_fetch_andnot in aic_handle_ipi().
		 */
		pending = atomic_fetch_or_release(irq_bit, per_cpu_ptr(&aic_vipi_flag, cpu));

		/*
		 * The atomic_fetch_or_release() above must complete before the
		 * atomic_read() below to avoid racing aic_ipi_unmask().
		 */
		smp_mb__after_atomic();

		if (!(pending & irq_bit) &&
		    (atomic_read(per_cpu_ptr(&aic_vipi_enable, cpu)) & irq_bit))
			send |= AIC_IPI_SEND_CPU(cpu);
	}

	/*
	 * The flag writes must complete before the physical IPI is issued
	 * to another CPU. This is implied by the control dependency on
	 * the result of atomic_read_acquire() above, which is itself
	 * already ordered after the vIPI flag write.
	 */
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

static void aic_handle_ipi(struct pt_regs *regs)
{
	int i;
	unsigned long enabled, firing;

	/*
	 * The mask read does not need to be ordered. Only we can change
	 * our own mask anyway, so no races are possible here, as long as
	 * we are properly in the interrupt handler (which is covered by
	 * the barrier that is part of the top-level AIC handler's readl()).
	 */
	enabled = atomic_read(this_cpu_ptr(&aic_vipi_enable));

	/*
	 * Clear the IPIs we are about to handle. This pairs with the
	 * atomic_fetch_or_release() in aic_ipi_send_mask(), and needs to be
	 * ordered after the aic_ic_write() above (to avoid dropping vIPIs) and
	 * before IPI handling code (to avoid races handling vIPIs before they
	 * are signaled). The former is taken care of by the release semantics
	 * of the write portion, while the latter is taken care of by the
	 * acquire semantics of the read portion.
	 */
	firing = atomic_fetch_andnot(enabled, this_cpu_ptr(&aic_vipi_flag)) & enabled;

	for_each_set_bit(i, &firing, AIC_NR_SWIPI)
		handle_domain_irq(aic_irqc->ipi_domain, i, regs);

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

	ipi_domain = irq_domain_create_linear(irqc->hw_domain->fwnode, AIC_NR_SWIPI,
					      &aic_ipi_domain_ops, irqc);
	if (WARN_ON(!ipi_domain))
		return -ENODEV;

	ipi_domain->flags |= IRQ_DOMAIN_FLAG_IPI_SINGLE;
	irq_domain_update_bus_token(ipi_domain, DOMAIN_BUS_IPI);

	base_ipi = __irq_domain_alloc_irqs(ipi_domain, -1, AIC_NR_SWIPI,
					   NUMA_NO_NODE, NULL, false, NULL);

	if (WARN_ON(base_ipi < 0)) {
		irq_domain_remove(ipi_domain);
		return -ENODEV;
	}

	set_smp_ipi_range(base_ipi, AIC_NR_SWIPI);

	irqc->ipi_domain = ipi_domain;

	return 0;
}

static int aic_init_cpu(unsigned int cpu)
{

	irqc = kzalloc(sizeof(*irqc), GFP_KERNEL);
	if (!irqc)
		return -ENOMEM;





	pr_info("Initialized with %d IRQs, %d FIQs, %d vIPIs\n",
		irqc->nr_hw, AIC_NR_FIQ, AIC_NR_SWIPI);

	return 0;
}
