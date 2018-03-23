#ifndef DBOX_SAVE_H
#define DBOX_SAVE_H

#include "dbox-storage.h"

struct dbox_save_context {
	struct mail_save_context ctx;
	struct mail_index_transaction *trans;

	/* updated for each appended mail: */
	uint32_t seq;
	struct istream *input;

	struct ostream *dbox_output;

	uint32_t highest_pop3_uidl_seq;
	bool failed:1;
	bool finished:1;
	bool have_pop3_uidls:1;
	bool have_pop3_orders:1;
};

#define DBOX_SAVECTX(s)		container_of(s, struct dbox_save_context, ctx)

void dbox_save_begin(struct dbox_save_context *ctx, struct istream *input);
int dbox_save_continue(struct mail_save_context *_ctx);
void dbox_save_end(struct dbox_save_context *ctx);

void dbox_save_write_metadata(struct mail_save_context *ctx,
			      struct ostream *output, uoff_t output_msg_size,
			      const char *orig_mailbox_name,
			      guid_128_t guid_128_r) ATTR_NULL(4);

void dbox_save_add_to_index(struct dbox_save_context *ctx);

void dbox_save_update_header_flags(struct dbox_save_context *ctx,
				   struct mail_index_view *sync_view,
				   uint32_t ext_id,
				   unsigned int flags_offset);

#endif
