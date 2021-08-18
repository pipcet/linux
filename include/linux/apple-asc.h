#include <linux/mailbox_client.h>
#include <linux/slab.h>
#include <linux/types.h>

/* A message at the physical mbox level. 64-bit payload plus 64-bit
 * information which includes, in its low-order bits, an 8-bit endpoint. */
struct apple_mbox_msg {
	u64 payload;
	u64 endpoint;
};

struct apple_dcp_msg_header {
	u32 code;
	u32 len_input;
	u32 len_output;
};

struct apple_dcp_mbox_msg {
	struct apple_mbox_msg mbox;
	struct apple_dcp_msg_header dcp;
	char dcp_data[];
};

struct apple_ans_msg_header {
	u32 code;
	u32 len_input;
	u32 len_output;
};

struct apple_ans_mbox_msg {
	struct apple_mbox_msg mbox;
	struct apple_ans_msg_header ans;
	char ans_data[];
};

#define EP0_TYPE_MASK		GENMASK(63, 52)
#define EP0_TYPE_HELLO		FIELD_PREP(EP0_TYPE_MASK, 0x001)
#define EP0_TYPE_EHLLO		FIELD_PREP(EP0_TYPE_MASK, 0x002)
#define EP0_TYPE_START		FIELD_PREP(EP0_TYPE_MASK, 0x005)
#define EP0_TYPE_RESET		FIELD_PREP(EP0_TYPE_MASK, 0x006)
#define EP0_TYPE_PWROK		FIELD_PREP(EP0_TYPE_MASK, 0x007)
#define EP0_TYPE_EPMAP		FIELD_PREP(EP0_TYPE_MASK, 0x008)
#define EP0_TYPE_PWRACK		FIELD_PREP(EP0_TYPE_MASK, 0x00b)

#define EP0_START	(EP0_TYPE_START | 0x0002)
#define EP0_EHLLO	(EP0_TYPE_EHLLO | BIT(32))
#define EP0_RESET	(EP0_TYPE_RESET | 0x0220)

#define EP0_EHLLO_MAGIC	0x000b000b

#define EP0_EPMAP_LAST		BIT(51)
#define EP0_EPMAP_PAGE_MASK	GENMASK(35, 32)
#define EP0_EPMAP_PAGE(p)	FIELD_GET(EP0_EPMAP_PAGE_MASK, (p))

#ifndef U36_MAX
#define U36_MAX			GENMASK(35, 0)
#endif

#ifndef U48_MAX
#define U48_MAX 		GENMASK(47, 0)
#endif

#define EP_TYPE_MASK		(0xfffULL << 52)
#define EP_TYPE_BUFFER		(0x001ULL << 52)
#define EP_TYPE_MESSAGE	(0x003ULL << 52)

#define ASC_TIMEOUT_MSEC	800

#define SMC_IRQ_BATT 0 /* battery charging/discharging/fully charged */
#define SMC_IRQ_HID  1 /* power button, lid switch */
#define SMC_IRQ_REST 2 /* unknown notification */
#define NUM_SMC_IRQ  3

/* Presumably there are temperature events, too, but no volunteers
 * have set their devices on fire, so far. */
#define SMC_NOTIFICATION_MASK  0xff00000000000000ULL
#define SMC_NOTIFICATION_BATT  0x7100000000000000ULL
#define SMC_NOTIFICATION_HID   0x7200000000000000ULL

struct rproc;
struct mbox_chan;

extern struct mbox_chan *apple_asc_lock_exclusively(struct rproc *);
extern void apple_asc_unlock(struct rproc *, bool);
extern void apple_asc_pwrack(struct rproc *);
extern int apple_dcp_transaction(struct mbox_chan *,
				 struct apple_dcp_mbox_msg *);

static inline int mbox_copy_and_send(struct mbox_chan *chan, void *ptr)
{
	struct apple_mbox_msg *msg = kzalloc(sizeof(*msg), GFP_KERNEL);
	memcpy(msg, ptr, sizeof(*msg));
	return mbox_send_message(chan, msg);
}
