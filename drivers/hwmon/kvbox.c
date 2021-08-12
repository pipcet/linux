/*
 * Key-Value Box support for Linux
 *
 * Copyright (C) 2021 Pip Cet <pipcet@gmail.com>
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
 */

#include <linux/slab.h>
#include <linux/of.h>
#include <linux/device.h>
#include <linux/module.h>

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
	struct kvbox_request *request = kzalloc(sizeof *request, GFP_KERNEL);
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
		kfree(request);
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

		kfree(request);
	}
}
EXPORT_SYMBOL(kvbox_done);

static LIST_HEAD(kvbox_cons);
static DEFINE_MUTEX(con_mutex);

int kvbox_register(struct kvbox *kvbox)
{
	mutex_lock(&con_mutex);
	list_add_tail(&kvbox->list, &kvbox_cons);
	mutex_unlock(&con_mutex);

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
	return kvbox;
}
EXPORT_SYMBOL(kvbox_request);

MODULE_LICENSE("GPL");
