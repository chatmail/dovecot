#ifndef MBOX_STORAGE_H
#define MBOX_STORAGE_H

#include "index-storage.h"
#include "mbox-settings.h"
#include "mbox-md5.h"

/* Padding to leave in X-Keywords header when rewriting mbox */
#define MBOX_HEADER_PADDING 50
/* Don't write Content-Length header unless it's value is larger than this. */
#define MBOX_MIN_CONTENT_LENGTH_SIZE 1024

#define MBOX_STORAGE_NAME "mbox"
#define MBOX_SUBSCRIPTION_FILE_NAME ".subscriptions"
#define MBOX_INDEX_DIR_NAME ".imap"
#define MBOX_UIDVALIDITY_FNAME "dovecot-uidvalidity"

struct mbox_index_header {
	uint64_t sync_size;
	uint32_t sync_mtime;
	uint8_t dirty_flag;
	uint8_t unused[3];
	guid_128_t mailbox_guid;
};

struct mbox_list_index_record {
	uint32_t mtime;
	uint32_t size;
};

struct mbox_storage {
	struct mail_storage storage;

	const struct mbox_settings *set;
	enum mbox_lock_type *read_locks;
	enum mbox_lock_type *write_locks;
	bool lock_settings_initialized:1;
};

struct mbox_mailbox {
	struct mailbox box;
	struct mbox_storage *storage;

	int mbox_fd;
	struct istream *mbox_stream, *mbox_file_stream;
	int mbox_lock_type;
	dev_t mbox_dev;
	ino_t mbox_ino;
	unsigned int mbox_excl_locks, mbox_shared_locks;
	struct dotlock *mbox_dotlock;
	unsigned int mbox_lock_id, mbox_global_lock_id;
	struct timeout *keep_lock_to;
	bool mbox_writeonly;
	unsigned int external_transactions;

	uint32_t mbox_ext_idx, md5hdr_ext_idx, mbox_list_index_ext_id;
	struct mbox_index_header mbox_hdr;
	const struct mailbox_update *sync_hdr_update;

	struct mbox_md5_vfuncs md5_v;

	bool no_mbox_file:1;
	bool invalid_mbox_file:1;
	bool mbox_broken_offsets:1;
	bool mbox_save_md5:1;
	bool mbox_dotlocked:1;
	bool mbox_used_privileges:1;
	bool mbox_privileged_locking:1;
	bool syncing:1;
	bool backend_readonly:1;
	bool backend_readonly_set:1;
};

struct mbox_transaction_context {
	struct mailbox_transaction_context t;
	union mail_index_transaction_module_context module_ctx;

	unsigned int read_lock_id;
	unsigned int write_lock_id;
};

#define MBOX_STORAGE(s)		container_of(s, struct mbox_storage, storage)
#define MBOX_MAILBOX(s)		container_of(s, struct mbox_mailbox, box)
#define MBOX_TRANSCTX(s)	container_of(s, struct mbox_transaction_context, t)

extern struct mail_vfuncs mbox_mail_vfuncs;
extern const char *mbox_hide_headers[], *mbox_save_drop_headers[];
extern unsigned int mbox_hide_headers_count, mbox_save_drop_headers_count;

void mbox_set_syscall_error(struct mbox_mailbox *mbox, const char *function);
void mbox_istream_set_syscall_error(struct mbox_mailbox *mbox,
				    struct istream *input,
				    const char *function);
void mbox_ostream_set_syscall_error(struct mbox_mailbox *mbox,
				    struct ostream *output,
				    const char *function);

struct mailbox_sync_context *
mbox_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags);

struct mail_save_context *
mbox_save_alloc(struct mailbox_transaction_context *_t);
int mbox_save_begin(struct mail_save_context *ctx, struct istream *input);
int mbox_save_continue(struct mail_save_context *ctx);
int mbox_save_finish(struct mail_save_context *ctx);
void mbox_save_cancel(struct mail_save_context *ctx);

int mbox_transaction_save_commit_pre(struct mail_save_context *ctx);
void mbox_transaction_save_commit_post(struct mail_save_context *ctx,
				       struct mail_index_transaction_commit_result *result);
void mbox_transaction_save_rollback(struct mail_save_context *ctx);

bool mbox_is_backend_readonly(struct mbox_mailbox *mbox);

#endif
