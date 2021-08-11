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

struct vipi_irq_chip {
	struct irq_domain *domain;
	struct irq_data *hwirq;
};

#define NR_SWIPI 32

static DEFINE_PER_CPU(atomic_t, vipi_flag);
static DEFINE_PER_CPU(atomic_t, vipi_enable);

static struct vipi_irq_chip *vipi_irqc;

static void handle_ipi(struct irq_desc *d);
/*
 * IPI irqchip
 */

static void vipi_mask(struct irq_data *d)
{
	u32 irq_bit = BIT(irqd_to_hwirq(d));

	/* No specific ordering requirements needed here. */
	atomic_andnot(irq_bit, this_cpu_ptr(&vipi_enable));
}

static void vipi_unmask(struct irq_data *d)
{
	struct vipi_irq_chip *ic = irq_data_get_irq_chip_data(d);
	u32 irq_bit = BIT(irqd_to_hwirq(d));

	atomic_or(irq_bit, this_cpu_ptr(&vipi_enable));

	/*
	 * The atomic_or() above must complete before the atomic_read()
	 * below to avoid racing aic_ipi_send_mask().
	 */
	smp_mb__after_atomic();

	/*
	 * If a pending vIPI was unmasked, raise a HW IPI to ourselves.
	 * No barriers needed here since this is a self-IPI.
	 */
	if (atomic_read(this_cpu_ptr(&vipi_flag)) & irq_bit) {
		struct cpumask self_mask = { 0, };
		cpumask_set_cpu(smp_processor_id(), &self_mask);
		ipi_send_mask(ic->hwirq->irq, &self_mask);
	}
}


static void vipi_send_mask(struct irq_data *d, const struct cpumask *mask)
{
	struct vipi_irq_chip *ic = irq_data_get_irq_chip_data(d);
	u32 irq_bit = BIT(irqd_to_hwirq(d));
	int cpu;
	bool send;
	unsigned long pending;
	struct cpumask sendmask = *mask;

	for_each_cpu(cpu, mask) {
		/*
		 * This sequence is the mirror of the one in vipi_unmask();
		 * see the comment there. Additionally, release semantics
		 * ensure that the vIPI flag set is ordered after any shared
		 * memory accesses that precede it. This therefore also pairs
		 * with the atomic_fetch_andnot in handle_ipi().
		 */
		pending = atomic_fetch_or_release(irq_bit, per_cpu_ptr(&vipi_flag, cpu));

		/*
		 * The atomic_fetch_or_release() above must complete before the
		 * atomic_read() below to avoid racing vipi_unmask().
		 */
		smp_mb__after_atomic();

		if (!(pending & irq_bit) &&
		    (atomic_read(per_cpu_ptr(&vipi_enable, cpu)) & irq_bit)) {
			cpumask_set_cpu(cpu, &sendmask);
			send = true;
		}
	}

	/*
	 * The flag writes must complete before the physical IPI is issued
	 * to another CPU. This is implied by the control dependency on
	 * the result of atomic_read_acquire() above, which is itself
	 * already ordered after the vIPI flag write.
	 */
	if (send)
		ipi_send_mask(ic->hwirq->irq, &sendmask);
}

static struct irq_chip vipi_chip = {
	.name = "VIPI",
	.irq_mask = vipi_mask,
	.irq_unmask = vipi_unmask,
	.ipi_send_mask = vipi_send_mask,
};

/*
 * IPI IRQ domain
 */

static void handle_ipi(struct irq_desc *d)
{
	int i;
	unsigned long enabled, firing;

	/*
	 * The mask read does not need to be ordered. Only we can change
	 * our own mask anyway, so no races are possible here, as long as
	 * we are properly in the interrupt handler (XXX is this satisfied?).
	 */
	enabled = atomic_read(this_cpu_ptr(&vipi_enable));

	/*
	 * Clear the IPIs we are about to handle. This pairs with the
	 * atomic_fetch_or_release() in vipi_send_mask(), and needs to be
	 * ordered after the ic_write() above (to avoid dropping vIPIs) and
	 * before IPI handling code (to avoid races handling vIPIs before they
	 * are signaled). The former is taken care of by the release semantics
	 * of the write portion, while the latter is taken care of by the
	 * acquire semantics of the read portion.
	 */
	firing = atomic_fetch_andnot(enabled, this_cpu_ptr(&vipi_flag)) & enabled;

	for_each_set_bit(i, &firing, NR_SWIPI) {
		struct irq_desc *nd =
			irq_resolve_mapping(vipi_irqc->domain, i);

		handle_irq_desc(nd);
	}
}

static int vipi_alloc(struct irq_domain *d, unsigned int virq,
		     unsigned int nr_irqs, void *args)
{
	int i;

	for (i = 0; i < nr_irqs; i++) {
		irq_set_percpu_devid(virq + i);
		irq_domain_set_info(d, virq + i, i, &vipi_chip, d->host_data,
				    handle_percpu_devid_irq, NULL, NULL);
	}

	return 0;
}

static void vipi_free(struct irq_domain *d, unsigned int virq, unsigned int nr_irqs)
{
	/* Not freeing IPIs */
	WARN_ON(1);
}

static const struct irq_domain_ops vipi_domain_ops = {
	.alloc = vipi_alloc,
	.free = vipi_free,
};

static int vipi_init_smp(struct vipi_irq_chip *irqc)
{
	struct irq_domain *vipi_domain;
	int base_ipi;

	vipi_domain = irq_domain_create_linear(NULL, NR_SWIPI,
					      &vipi_domain_ops, irqc);
	if (WARN_ON(!vipi_domain))
		return -ENOMEM;

	vipi_domain->flags |= IRQ_DOMAIN_FLAG_IPI_SINGLE;
	irq_domain_update_bus_token(vipi_domain, DOMAIN_BUS_IPI);

	base_ipi = __irq_domain_alloc_irqs(vipi_domain, -1, NR_SWIPI,
					   NUMA_NO_NODE, NULL, false, NULL);

	if (WARN_ON(!base_ipi)) {
		irq_domain_remove(vipi_domain);
		return -ENOMEM;
	}

	set_smp_ipi_range(base_ipi, NR_SWIPI);

	irqc->domain = vipi_domain;

	return 0;
}

int __init vipi_init(struct irq_data *hwirq)
{
	struct vipi_irq_chip *irqc;

	irqc = kzalloc(sizeof(*irqc), GFP_KERNEL);
	if (!irqc)
		return -ENOMEM;

	irqc->hwirq = hwirq;

	if (vipi_init_smp(irqc))
		return -ENOMEM;

	vipi_irqc = irqc;

	irq_set_handler_locked(hwirq, handle_ipi);

	pr_info("Initialized with %d vIPIs\n", NR_SWIPI);

	return 0;
}
