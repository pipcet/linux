struct kvbox_prop {
	size_t key_len;
	const void *key;
	size_t data_len;
	void *data;
	const char *type;
	const char *extra;
};

typedef void (*kvbox_cb_t)(void *priv);

struct kvbox_request {
	struct list_head list;
	struct completion tx_complete;
	struct kvbox *kvbox;
	kvbox_cb_t callback;
	void *priv;
};

struct kvbox_ops {
	int (*read)(struct kvbox *kvbox, struct kvbox_prop *prop);
	int (*write)(struct kvbox *kvbox, struct kvbox_prop *prop);
};

struct kvbox {
	struct list_head list;
	struct device *dev;
	const struct kvbox_ops *ops;
	struct list_head requests;
	struct kvbox_prop *known_props;
	size_t num_known_props;
	void *priv;

	struct dentry *debugfs_dir;
};

extern int kvbox_read(struct kvbox *kvbox,
		      struct kvbox_prop *prop,
		      kvbox_cb_t callback, void *priv);

extern int kvbox_write(struct kvbox *kvbox,
		       struct kvbox_prop *prop,
		       kvbox_cb_t callback, void *priv);

extern int kvbox_read_interruptible(struct kvbox *kvbox, struct kvbox_prop *prop);
extern int kvbox_write_interruptible(struct kvbox *kvbox, struct kvbox_prop *prop);

extern int kvbox_fake_request(struct kvbox *kvbox,
			      kvbox_cb_t callback, void *priv);

extern void kvbox_done(struct kvbox *kvbox);
extern int kvbox_register(struct kvbox *kvbox);
extern struct kvbox *kvbox_request(struct device *dev, int index);
