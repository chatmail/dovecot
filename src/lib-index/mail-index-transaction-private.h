#ifndef MAIL_INDEX_TRANSACTION_PRIVATE_H
#define MAIL_INDEX_TRANSACTION_PRIVATE_H

#include "seq-range-array.h"
#include "mail-transaction-log.h"

struct mail_index_transaction_keyword_update {
	ARRAY_TYPE(seq_range) add_seq;
	ARRAY_TYPE(seq_range) remove_seq;
};

struct mail_index_transaction_ext_hdr_update {
	size_t alloc_size;
	/* mask is in bytes, not bits */
	unsigned char *mask;
	unsigned char *data;
};

struct mail_index_transaction_vfuncs {
	int (*commit)(struct mail_index_transaction *t,
		      uint32_t *log_file_seq_r, uoff_t *log_file_offset_r);
	void (*rollback)(struct mail_index_transaction *t);
};

union mail_index_transaction_module_context {
	struct mail_index_module_register *reg;
};

struct mail_index_transaction {
	int refcount;

	enum mail_index_transaction_flags flags;
	struct mail_index_transaction_vfuncs v;
	struct mail_index_view *view;

	/* NOTE: If you add anything new, remember to update
	   mail_index_transaction_reset() to reset it. */
        ARRAY_DEFINE(appends, struct mail_index_record);
	uint32_t first_new_seq, last_new_seq;
	uint32_t highest_append_uid;
	/* lowest/highest sequence that updates flags/keywords */
	uint32_t min_flagupdate_seq, max_flagupdate_seq;

	ARRAY_TYPE(seq_range) expunges;
	ARRAY_DEFINE(updates, struct mail_transaction_flag_update);
	size_t last_update_idx;

	unsigned char pre_hdr_change[sizeof(struct mail_index_header)];
	unsigned char pre_hdr_mask[sizeof(struct mail_index_header)];
	unsigned char post_hdr_change[sizeof(struct mail_index_header)];
	unsigned char post_hdr_mask[sizeof(struct mail_index_header)];

	ARRAY_DEFINE(ext_hdr_updates,
		     struct mail_index_transaction_ext_hdr_update);
	ARRAY_DEFINE(ext_rec_updates, ARRAY_TYPE(seq_array));
	ARRAY_DEFINE(ext_resizes, struct mail_transaction_ext_intro);
	ARRAY_DEFINE(ext_resets, struct mail_transaction_ext_reset);
	ARRAY_DEFINE(ext_reset_ids, uint32_t);
	ARRAY_DEFINE(ext_reset_atomic, uint32_t);

	ARRAY_DEFINE(keyword_updates,
		     struct mail_index_transaction_keyword_update);
	ARRAY_TYPE(seq_range) keyword_resets;

	uint64_t max_modseq;
	ARRAY_TYPE(seq_range) *conflict_seqs;

        struct mail_cache_transaction_ctx *cache_trans_ctx;

	/* Module-specific contexts. */
	ARRAY_DEFINE(module_contexts,
		     union mail_index_transaction_module_context *);

	unsigned int no_appends:1;

	unsigned int sync_transaction:1;
	unsigned int appends_nonsorted:1;
	unsigned int pre_hdr_changed:1;
	unsigned int post_hdr_changed:1;
	unsigned int reset:1;
	/* non-extension updates. flag updates don't change this because
	   they may be added and removed, so be sure to check that the updates
	   array is non-empty also. */
	unsigned int log_updates:1;
	/* extension updates */
	unsigned int log_ext_updates:1;
};

extern void (*hook_mail_index_transaction_created)
		(struct mail_index_transaction *t);

struct mail_index_record *
mail_index_transaction_lookup(struct mail_index_transaction *t, uint32_t seq);

void mail_index_transaction_ref(struct mail_index_transaction *t);
void mail_index_transaction_unref(struct mail_index_transaction **t);

void mail_index_transaction_sort_appends(struct mail_index_transaction *t);
uint32_t mail_index_transaction_get_next_uid(struct mail_index_transaction *t);
void mail_index_transaction_convert_to_uids(struct mail_index_transaction *t);
void mail_index_transaction_check_conflicts(struct mail_index_transaction *t);

unsigned int
mail_index_transaction_get_flag_update_pos(struct mail_index_transaction *t,
					   unsigned int left_idx,
					   unsigned int right_idx,
					   uint32_t seq);

bool mail_index_seq_array_lookup(const ARRAY_TYPE(seq_array) *array,
				 uint32_t seq, unsigned int *idx_r);

#endif