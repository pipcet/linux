/*
 * Key-Value Box support for Linux.
 *
 * Based heavily on the mailbox code, which is
 * Copyright (C) 2013-2014 Linaro Ltd.
 * Author: Jassi Brar <jassisinghbrar@gmail.com>
 *
 * Key-value boxes differ from mailboxes in a few ways:
 *
 *  1. they have a large number of keys to be used rather than a small
 *  number of channels.
 *
 *  2. there's currently no way of ensuring exclusive access.
 *
 *  3. reading a key should never have any major side effects.
 */

#include <linux/slab.h>
#include <linux/of.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/debugfs.h>

#include "kvbox.h"

static int kvbox_fake_request_r(struct kvbox *kvbox,
				struct kvbox_prop *prop)
{
	return 0;
}

static int kvbox_make_request(struct kvbox *kvbox, struct kvbox_prop *prop,
			      int (*r)(struct kvbox *, struct kvbox_prop *),
			      kvbox_cb_t callback, void *priv)
{
	struct kvbox_request *request =
                devm_kzalloc(kvbox->dev, sizeof *request, GFP_KERNEL);
	int ret;

	if (!request)
		return -ENOMEM;

	init_completion(&request->tx_complete);
	request->kvbox = kvbox;
	request->callback = callback;
	request->priv = priv;
	list_add(&request->list, &kvbox->requests);

	ret = r(kvbox, prop);

	if (ret < 0) {
		devm_kfree(kvbox->dev, request);
		return ret;
	}

	return 0;
}

int kvbox_read(struct kvbox *kvbox,
	       struct kvbox_prop *prop,
	       kvbox_cb_t callback, void *priv)
{
	return kvbox_make_request(kvbox, prop, kvbox->ops->read, callback, priv);
}
EXPORT_SYMBOL(kvbox_read);

int kvbox_write(struct kvbox *kvbox,
		struct kvbox_prop *prop,
		kvbox_cb_t callback, void *priv)
{
	return kvbox_make_request(kvbox, prop, kvbox->ops->write, callback, priv);
}
EXPORT_SYMBOL(kvbox_write);

int kvbox_fake_request(struct kvbox *kvbox,
		       kvbox_cb_t callback, void *priv)
{
	return kvbox_make_request(kvbox, NULL, kvbox_fake_request_r,
				  callback, priv);
}
EXPORT_SYMBOL(kvbox_fake_request);

void kvbox_done(struct kvbox *kvbox)
{
	struct kvbox_request *request;

	WARN_ON(list_empty(&kvbox->requests));
	if (list_empty(&kvbox->requests))
		return;

	while (!list_empty(&kvbox->requests)) {
		request = list_first_entry(&kvbox->requests, struct kvbox_request,
					   list);

		list_del(&request->list);
		request->callback(request->priv);

		devm_kfree(kvbox->dev, request);
	}
}
EXPORT_SYMBOL(kvbox_done);

static LIST_HEAD(kvbox_cons);
static DEFINE_MUTEX(con_mutex);

struct kvbox_debugfs_data {
	struct kvbox *kvbox;
	struct kvbox_prop *prop;
};

struct kvbox_debugfs_attr {
	struct device_attribute device_attr;
	struct kvbox_debugfs_data debugfs_data;
};

static void kvbox_complete(void *ptr)
{
	struct completion *c = ptr;

	complete_all(c);
}

static int kvbox_debugfs_key_show(struct seq_file *s, void *ptr)
{
	struct kvbox_debugfs_data *debugfs_data = s->private;
	struct kvbox_prop prop;
	int ret;

	memcpy(&prop, debugfs_data->prop, sizeof prop);

	ret = seq_write(s, prop.key, prop.key_len);

	return ret;
}
DEFINE_SHOW_ATTRIBUTE(kvbox_debugfs_key);

static int kvbox_debugfs_create_prop_key(struct kvbox *kvbox, struct kvbox_prop *prop,
					 struct dentry *dentry)
{
	struct kvbox_debugfs_data *data = devm_kzalloc(kvbox->dev, sizeof *data, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->kvbox = kvbox;
	data->prop = prop;

	debugfs_create_file("key", 0400, dentry, data, &kvbox_debugfs_key_fops);

	return 0;
}

static int kvbox_debugfs_extra_show(struct seq_file *s, void *ptr)
{
	struct kvbox_debugfs_data *debugfs_data = s->private;
	struct kvbox_prop prop;

	memcpy(&prop, debugfs_data->prop, sizeof prop);

	seq_printf(s, "%s\n", prop.extra);

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(kvbox_debugfs_extra);

static int kvbox_debugfs_create_prop_extra(struct kvbox *kvbox, struct kvbox_prop *prop,
					   struct dentry *dentry)
{
	struct kvbox_debugfs_data *data = devm_kzalloc(kvbox->dev, sizeof *data, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->kvbox = kvbox;
	data->prop = prop;

	debugfs_create_file("extra", 0400, dentry, data, &kvbox_debugfs_extra_fops);

	return 0;
}

static int kvbox_debugfs_type_show(struct seq_file *s, void *ptr)
{
	struct kvbox_debugfs_data *debugfs_data = s->private;
	struct kvbox_prop prop;

	memcpy(&prop, debugfs_data->prop, sizeof prop);

	seq_printf(s, "%s\n", prop.type);

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(kvbox_debugfs_type);

static int kvbox_debugfs_create_prop_type(struct kvbox *kvbox, struct kvbox_prop *prop,
					  struct dentry *dentry)
{
	struct kvbox_debugfs_data *data = devm_kzalloc(kvbox->dev, sizeof *data, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->kvbox = kvbox;
	data->prop = prop;

	debugfs_create_file("type", 0400, dentry, data, &kvbox_debugfs_type_fops);

	return 0;
}

static int kvbox_debugfs_size_show(struct seq_file *s, void *ptr)
{
	struct kvbox_debugfs_data *debugfs_data = s->private;
	struct kvbox_prop prop;

	memcpy(&prop, debugfs_data->prop, sizeof prop);

	seq_printf(s, "%lld\n", (long long)prop.data_len);

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(kvbox_debugfs_size);

static int kvbox_debugfs_create_prop_size(struct kvbox *kvbox, struct kvbox_prop *prop,
					  struct dentry *dentry)
{
	struct kvbox_debugfs_data *data = devm_kzalloc(kvbox->dev, sizeof *data, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->kvbox = kvbox;
	data->prop = prop;

	debugfs_create_file("size", 0400, dentry, data, &kvbox_debugfs_size_fops);

	return 0;
}

static int kvbox_debugfs_value_show(struct seq_file *s, void *ptr)
{
	struct kvbox_debugfs_data *debugfs_data = s->private;
	struct kvbox *kvbox = debugfs_data->kvbox;
	struct kvbox_prop prop;
	struct completion c;
	void *buf;

	memcpy(&prop, debugfs_data->prop, sizeof prop);

	buf = devm_kzalloc(kvbox->dev, prop.data_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	prop.data = buf;

	init_completion(&c);

	kvbox_read(kvbox, &prop, kvbox_complete, &c);

	wait_for_completion(&c);

	seq_write(s, prop.data, prop.data_len);

	devm_kfree(kvbox->dev, buf);

	return 0;
}

static ssize_t kvbox_debugfs_value_write(struct file *file,
					 const char __user *user_buf,
					 size_t size, loff_t *ppos)
{
	struct seq_file *s = file->private_data;
	struct kvbox_debugfs_data *debugfs_data = s->private;
	struct kvbox *kvbox = debugfs_data->kvbox;
	struct kvbox_prop prop;
	struct completion c;
	void *buf;

	memcpy(&prop, debugfs_data->prop, sizeof prop);
	if (size != prop.data_len)
		return -EINVAL;

	buf = devm_kzalloc(kvbox->dev, prop.data_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	prop.data = buf;

	if (copy_from_user(buf, user_buf, size)) {
		devm_kfree(kvbox->dev, buf);
		return -EFAULT;
	}
	*ppos += size;

	init_completion(&c);

	kvbox_write(kvbox, &prop, kvbox_complete, &c);

	wait_for_completion(&c);

	devm_kfree(kvbox->dev, buf);

	return size;
}

DEFINE_SHOW_ATTRIBUTE(kvbox_debugfs_value);
static const struct file_operations real_kvbox_debugfs_value_fops = {
	.owner = THIS_MODULE,
	.open = kvbox_debugfs_value_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = kvbox_debugfs_value_write,
};

static int kvbox_debugfs_create_prop_value(struct kvbox *kvbox, struct kvbox_prop *prop,
					   struct dentry *dentry)
{
	struct kvbox_debugfs_data *data = devm_kzalloc(kvbox->dev, sizeof *data, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->kvbox = kvbox;
	data->prop = prop;

	debugfs_create_file("value", 0600, dentry, data, &real_kvbox_debugfs_value_fops);

	return 0;
}

static int kvbox_debugfs_create_prop(struct kvbox *kvbox, struct kvbox_prop *prop)
{
	struct dentry *dentry;
	char *key;

	if (memchr(prop->key, 0, prop->key_len) ||
	    memchr(prop->key, '/', prop->key_len))
		return -EINVAL;

	key = devm_kzalloc(kvbox->dev, prop->key_len + 1, GFP_KERNEL);
	if (!key)
		return -ENOMEM;

	memcpy(key, prop->key, prop->key_len);

	dentry = debugfs_create_dir(prop->key, kvbox->debugfs_dir);

	if (!dentry)
		return -ENOMEM;

	kvbox_debugfs_create_prop_value(kvbox, prop, dentry);
	kvbox_debugfs_create_prop_type(kvbox, prop, dentry);
	kvbox_debugfs_create_prop_size(kvbox, prop, dentry);
	kvbox_debugfs_create_prop_extra(kvbox, prop, dentry);
	kvbox_debugfs_create_prop_key(kvbox, prop, dentry);

	return 0;
}

static struct dentry *kvbox_debugfs_dir;

static int kvbox_debugfs_create(struct kvbox *kvbox)
{
	size_t i;

	if (!kvbox_debugfs_dir)
		kvbox_debugfs_dir = debugfs_create_dir("kvbox", NULL);

	if (!kvbox_debugfs_dir) {
		printk("no dir\n");
		return -ENOMEM;
	}

	kvbox->debugfs_dir = debugfs_create_dir(dev_name(kvbox->dev), kvbox_debugfs_dir);
	if (!kvbox->debugfs_dir) {
		printk("no dir 2\n");
		return -ENOMEM;
	}

	for (i = 0; i < kvbox->num_known_props; i++)
		kvbox_debugfs_create_prop(kvbox, &kvbox->known_props[i]);

	return 0;
}

int kvbox_register(struct kvbox *kvbox)
{
	mutex_lock(&con_mutex);
	list_add_tail(&kvbox->list, &kvbox_cons);
	mutex_unlock(&con_mutex);
	kvbox_debugfs_create(kvbox);

	return 0;
}
EXPORT_SYMBOL(kvbox_register);

struct kvbox *kvbox_request(struct device *dev, int index)
{
	struct of_phandle_args spec;
	struct kvbox *kvbox;
	mutex_lock(&con_mutex);
	if (of_parse_phandle_with_args(dev->of_node, "kvboxes",
				       "#kvbox-cells", index, &spec)) {
		mutex_unlock(&con_mutex);
		return ERR_PTR(-ENODEV);
	}

	list_for_each_entry(kvbox, &kvbox_cons, list)
		if (kvbox->dev->of_node == spec.np)
			goto out;

	kvbox = ERR_PTR(-EPROBE_DEFER);
  out:
	of_node_put(spec.np);
	mutex_unlock(&con_mutex);
	return kvbox;
}
EXPORT_SYMBOL(kvbox_request);

int kvbox_read_interruptible(struct kvbox *kvbox, struct kvbox_prop *prop)
{
	int ret;
	struct completion c;

	init_completion(&c);

	ret = kvbox_read(kvbox, prop, kvbox_complete, &c);
	if (ret < 0)
		return ret;

	ret = wait_for_completion_interruptible_timeout
		(&c, 5 * HZ);
	if (ret < 0)
		return ret;

	return 0;
}
EXPORT_SYMBOL(kvbox_read_interruptible);

int kvbox_write_interruptible(struct kvbox *kvbox, struct kvbox_prop *prop)
{
	int ret;
	struct completion c;

	init_completion(&c);

	ret = kvbox_write(kvbox, prop, kvbox_complete, &c);
	if (ret < 0)
		return ret;

	ret = wait_for_completion_interruptible_timeout
		(&c, 5 * HZ);
	if (ret < 0)
		return ret;

	return 0;
}
EXPORT_SYMBOL(kvbox_write_interruptible);

MODULE_LICENSE("GPL");
