#ifndef MAIL_INDEX_TRANSACTION_PRIVATE_H
#define MAIL_INDEX_TRANSACTION_PRIVATE_H

#include "seq-range-array.h"
#include "mail-transaction-log.h"

ARRAY_DEFINE_TYPE(seq_array_array, ARRAY_TYPE(seq_array));

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
	void (*reset)(struct mail_index_transaction *t);
	int (*commit)(struct mail_index_transaction *t,
		      struct mail_index_transaction_commit_result *result_r);
	void (*rollback)(struct mail_index_transaction *t);
};

union mail_index_transaction_module_context {
	struct mail_index_transaction_vfuncs super;
	struct mail_index_module_register *reg;
};

struct mail_index_flag_update {
	uint32_t uid1, uid2;
	uint16_t add_flags;
	uint16_t remove_flags;
};

struct mail_index_transaction {
	struct mail_index_transaction *prev, *next;
	int refcount;

	enum mail_index_transaction_flags flags;
	struct mail_index_transaction_vfuncs v, *vlast;
	struct mail_index_view *view;
	struct mail_index_view *latest_view;

	/* NOTE: If you add anything new, remember to update
	   mail_index_transaction_reset_v() to reset it. */
        ARRAY(struct mail_index_record) appends;
	uint32_t first_new_seq, last_new_seq;
	uint32_t highest_append_uid;
	/* lowest/highest sequence that updates flags/keywords */
	uint32_t min_flagupdate_seq, max_flagupdate_seq;

	ARRAY(struct mail_transaction_modseq_update) modseq_updates;
	ARRAY(struct mail_transaction_expunge_guid) expunges;
	ARRAY(struct mail_index_flag_update) updates;
	size_t last_update_idx;

	unsigned char pre_hdr_change[sizeof(struct mail_index_header)];
	unsigned char pre_hdr_mask[sizeof(struct mail_index_header)];
	unsigned char post_hdr_change[sizeof(struct mail_index_header)];
	unsigned char post_hdr_mask[sizeof(struct mail_index_header)];

	ARRAY(struct mail_index_transaction_ext_hdr_update) ext_hdr_updates;
	ARRAY_TYPE(seq_array_array) ext_rec_updates;
	ARRAY_TYPE(seq_array_array) ext_rec_atomics;
	ARRAY(struct mail_transaction_ext_intro) ext_resizes;
	ARRAY(struct mail_transaction_ext_reset) ext_resets;
	ARRAY(uint32_t) ext_reset_ids;
	ARRAY(uint32_t) ext_reset_atomic;

	ARRAY(struct mail_index_transaction_keyword_update) keyword_updates;
	buffer_t *attribute_updates; /* [+-][ps]key\0.. */
	buffer_t *attribute_updates_suffix; /* <timestamp>[<value len>].. */

	uint64_t min_highest_modseq;
	uint64_t max_modseq;
	ARRAY_TYPE(seq_range) *conflict_seqs;

	/* Module-specific contexts. */
	ARRAY(union mail_index_transaction_module_context *) module_contexts;

	bool no_appends:1;

	bool sync_transaction:1;
	bool appends_nonsorted:1;
	bool expunges_nonsorted:1;
	bool drop_unnecessary_flag_updates:1;
	bool pre_hdr_changed:1;
	bool post_hdr_changed:1;
	bool reset:1;
	bool index_deleted:1;
	bool index_undeleted:1;
	bool commit_deleted_index:1;
	bool tail_offset_changed:1;
	/* non-extension updates. flag updates don't change this because
	   they may be added and removed, so be sure to check that the updates
	   array is non-empty also. */
	bool log_updates:1;
	/* extension updates */
	bool log_ext_updates:1;
};

#define MAIL_INDEX_TRANSACTION_HAS_CHANGES(t) \
	((t)->log_updates || (t)->log_ext_updates || \
	 (array_is_created(&(t)->updates) && array_count(&(t)->updates) > 0) || \
	 (t)->index_deleted || (t)->index_undeleted)

typedef void hook_mail_index_transaction_created_t(struct mail_index_transaction *t);

void mail_index_transaction_hook_register(hook_mail_index_transaction_created_t *hook);
void mail_index_transaction_hook_unregister(hook_mail_index_transaction_created_t *hook);

struct mail_index_record *
mail_index_transaction_lookup(struct mail_index_transaction *t, uint32_t seq);

void mail_index_transaction_ref(struct mail_index_transaction *t);
void mail_index_transaction_unref(struct mail_index_transaction **t);
void mail_index_transaction_reset_v(struct mail_index_transaction *t);

void mail_index_transaction_sort_appends(struct mail_index_transaction *t);
void mail_index_transaction_sort_expunges(struct mail_index_transaction *t);
uint32_t mail_index_transaction_get_next_uid(struct mail_index_transaction *t);
void mail_index_transaction_set_log_updates(struct mail_index_transaction *t);
void mail_index_update_day_headers(struct mail_index_transaction *t, time_t day_stamp);

unsigned int
mail_index_transaction_get_flag_update_pos(struct mail_index_transaction *t,
					   unsigned int left_idx,
					   unsigned int right_idx,
					   uint32_t seq);
void mail_index_transaction_lookup_latest_keywords(struct mail_index_transaction *t,
						   uint32_t seq,
						   ARRAY_TYPE(keyword_indexes) *keywords);

bool mail_index_cancel_flag_updates(struct mail_index_transaction *t,
				    uint32_t seq);
bool mail_index_cancel_keyword_updates(struct mail_index_transaction *t,
				       uint32_t seq);

/* As input the array's each element starts with struct seq_range where
   uid1..uid2 are actually sequences within the transaction view. This function
   changes the sequences into UIDs. If the transaction has any appends, they
   must have already been assigned UIDs. */
void mail_index_transaction_seq_range_to_uid(struct mail_index_transaction *t,
					     ARRAY_TYPE(seq_range) *array);
void mail_index_transaction_finish_so_far(struct mail_index_transaction *t);
void mail_index_transaction_finish(struct mail_index_transaction *t);
void mail_index_transaction_export(struct mail_index_transaction *t,
				   struct mail_transaction_log_append_ctx *append_ctx,
				   enum mail_index_transaction_change *changes_r);
int mail_transaction_expunge_guid_cmp(const struct mail_transaction_expunge_guid *e1,
				      const struct mail_transaction_expunge_guid *e2);
unsigned int
mail_index_transaction_get_flag_update_pos(struct mail_index_transaction *t,
					   unsigned int left_idx,
					   unsigned int right_idx,
					   uint32_t seq);

void mail_index_ext_using_reset_id(struct mail_index_transaction *t,
				   uint32_t ext_id, uint32_t reset_id);

#endif
