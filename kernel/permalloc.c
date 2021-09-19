#include <linux/permalloc.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/slab.h>

static struct list_head permallocs;

static struct dentry *permalloc_debugfs_dir;

static int permalloc_debugfs_show(struct seq_file *s, void *ptr)
{
	struct permalloc_entry *entry;

	list_for_each_entry(entry, &permallocs, list) {
		seq_printf(s, "%s\n", entry->str);
	}

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(permalloc_debugfs);

static void permalloc_init(void)
{
	INIT_LIST_HEAD(&permallocs);

	permalloc_debugfs_dir = debugfs_create_dir("permallocs", NULL);

	debugfs_create_file("permallocs", 0400, permalloc_debugfs_dir, NULL, &permalloc_debugfs_fops);
}

int permalloc_bool(struct device *dev, const char *name)
{
	char *str;
	struct permalloc_entry *entry;
	if (!permalloc_debugfs_dir)
		permalloc_init();

	str = devm_kasprintf(dev, GFP_KERNEL, "%s: %s;",
			     dev_name(dev), name);
	entry = kzalloc(sizeof *entry, GFP_KERNEL);
	if (!str || !entry)
		return -ENOMEM;

	entry->dev = dev;
	entry->str = str;
	list_add(&entry->list, &permallocs);

	return 0;
}

int permalloc_memory(struct device *dev, void *memory, size_t size)
{
	phys_addr_t phys_addr;
	char *str;
	struct permalloc_entry *entry;

	if (!permalloc_debugfs_dir)
		permalloc_init();

	while (size > PAGE_SIZE) {
		permalloc_memory(dev, memory, PAGE_SIZE);
		size -= PAGE_SIZE;
		memory += PAGE_SIZE;
	}

	phys_addr = virt_to_phys(memory);
	str = devm_kasprintf(dev, GFP_KERNEL, "reserved: <%08llx %08llx %08llx %08llx>;",
			     (u64)(phys_addr & U32_MAX), ((u64)phys_addr >> 32),
			     (u64)(size & U32_MAX), (u64)0);
	entry = kzalloc(sizeof *entry, GFP_KERNEL);

	if (!str || !entry)
		return -ENOMEM;

	entry->dev = dev;
	entry->str = str;
	list_add(&entry->list, &permallocs);

	return 0;
}
