#ifndef _LINUX_PERMALLOC_H
#define _LINUX_PERMALLOC_H

#include <linux/list.h>

struct permalloc_entry {
	struct list_head list;
	struct device *dev;
	const char *str;
};

extern int permalloc_bool(struct device *dev, const char *name);
extern int permalloc_memory(struct device *dev, void *memory, size_t size);
extern int permalloc_spin_table(phys_addr_t spin_table_pa);
extern int permalloc_spin_code(phys_addr_t spin_code_pa);
#endif
