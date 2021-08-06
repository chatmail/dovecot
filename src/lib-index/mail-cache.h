#ifndef MAIL_CACHE_H
#define MAIL_CACHE_H

#include "mail-index.h"

#define MAIL_CACHE_FILE_SUFFIX ".cache"

struct mail_cache;
struct mail_cache_view;
struct mail_cache_transaction_ctx;

enum mail_cache_decision_type {
	/* Not needed currently */
	MAIL_CACHE_DECISION_NO		= 0x00,
	/* Needed only for new mails. Drop when purging. */
	MAIL_CACHE_DECISION_TEMP	= 0x01,
	/* Needed. */
	MAIL_CACHE_DECISION_YES		= 0x02,

	/* This decision has been forced manually, don't change it. */
	MAIL_CACHE_DECISION_FORCED	= 0x80
};

enum mail_cache_field_type {
	/* Fixed size cache field. The size is specified only in the cache
	   field header, not separately for each record. */
	MAIL_CACHE_FIELD_FIXED_SIZE,
	/* Variable sized binary data. */
	MAIL_CACHE_FIELD_VARIABLE_SIZE,
	/* Variable sized string. There is no difference internally to how
	   MAIL_CACHE_FIELD_VARIABLE_SIZE is handled, but it helps at least
	   "doveadm dump" to know whether to hex-encode the output. */
	MAIL_CACHE_FIELD_STRING,
	/* A fixed size bitmask field. It's possible to add new bits by
	   updating this field. All the added fields are ORed together. */
	MAIL_CACHE_FIELD_BITMASK,
	/* Variable sized message header. The data begins with a 0-terminated
	   uint32_t line_numbers[]. The line number exists only for each
	   header, header continuation lines in multiline headers don't get
	   listed. After the line numbers comes the list of headers, including
	   the "header-name: " prefix for each line, LFs and the TABs or spaces
	   for continued lines. */
	MAIL_CACHE_FIELD_HEADER,

	MAIL_CACHE_FIELD_COUNT
};

struct mail_cache_field {
	/* Unique name for the cache field. The field name doesn't matter
	   internally. */
	const char *name;
	/* Field index name. Used to optimize accessing the cache field. */
	unsigned int idx;

	/* Type of the field */
	enum mail_cache_field_type type;
	/* Size of the field, if it's a fixed size type. */
	unsigned int field_size;
	/* Current caching decision */
	enum mail_cache_decision_type decision;
	/* Timestamp when the cache field was last intentionally read (e.g.
	   by an IMAP client). Saving new mails doesn't update this field.
	   This is used to track when an unaccessed field should be dropped. */
	time_t last_used;
};

struct mail_cache *mail_cache_open_or_create(struct mail_index *index);
struct mail_cache *
mail_cache_open_or_create_path(struct mail_index *index, const char *path);
void mail_cache_free(struct mail_cache **cache);

/* Register fields. fields[].idx is updated to contain field index.
   If field already exists and its caching decision is NO, the decision is
   updated to the input field's decision. */
void mail_cache_register_fields(struct mail_cache *cache,
				struct mail_cache_field *fields,
				unsigned int fields_count);
/* Returns registered field index, or UINT_MAX if not found. */
unsigned int
mail_cache_register_lookup(struct mail_cache *cache, const char *name);
/* Returns specified field */
const struct mail_cache_field *
mail_cache_register_get_field(struct mail_cache *cache, unsigned int field_idx);
/* Returns a list of all registered fields */
struct mail_cache_field *
mail_cache_register_get_list(struct mail_cache *cache, pool_t pool,
			     unsigned int *count_r);

/* Returns TRUE if cache should be purged. */
bool mail_cache_need_purge(struct mail_cache *cache, const char **reason_r);
/* Set cache file to be purged later. */
void mail_cache_purge_later(struct mail_cache *cache, const char *reason);
/* Don't try to purge the cache file later after all. */
void mail_cache_purge_later_reset(struct mail_cache *cache);
/* Purge cache file. Offsets are updated to given transaction.
   The transaction log must already be exclusively locked.

   The cache purging is done only if the current cache file's file_seq
   matches purge_file_seq. The idea is that purging isn't done if
   another process had just purged it. 0 means the cache file is created
   only if it didn't already exist. (uint32_t)-1 means that purging is
   done always regardless of file_seq. */
int mail_cache_purge_with_trans(struct mail_cache *cache,
				struct mail_index_transaction *trans,
				uint32_t purge_file_seq, const char *reason);
int mail_cache_purge(struct mail_cache *cache, uint32_t purge_file_seq,
		     const char *reason);
/* Returns TRUE if there is at least something in the cache. */
bool mail_cache_exists(struct mail_cache *cache);
/* Open and read cache header. Returns 1 if ok, 0 if cache doesn't exist or it
   was corrupted and just got deleted, -1 if I/O error. */
int mail_cache_open_and_verify(struct mail_cache *cache);

struct mail_cache_view *
mail_cache_view_open(struct mail_cache *cache, struct mail_index_view *iview);
void mail_cache_view_close(struct mail_cache_view **view);

/* Normally cache decisions are updated on lookup/add. Use this function to
   enable/disable this (useful for precaching data). */
void mail_cache_view_update_cache_decisions(struct mail_cache_view *view,
					    bool update);

/* Copy caching decisions. This is expected to be called only for a newly
   created empty mailbox. */
int mail_cache_decisions_copy(struct mail_cache *src, struct mail_cache *dst);

/* Get index transaction specific cache transaction. */
struct mail_cache_transaction_ctx *
mail_cache_get_transaction(struct mail_cache_view *view,
			   struct mail_index_transaction *t);

void mail_cache_transaction_reset(struct mail_cache_transaction_ctx *ctx);
int mail_cache_transaction_commit(struct mail_cache_transaction_ctx **ctx);
void mail_cache_transaction_rollback(struct mail_cache_transaction_ctx **ctx);

/* Add new field to given record. Updates are not allowed. Fixed size fields
   must be exactly the expected size. */
void mail_cache_add(struct mail_cache_transaction_ctx *ctx, uint32_t seq,
		    unsigned int field_idx, const void *data, size_t data_size);
/* Returns TRUE if field is wanted to be added and it doesn't already exist.
   If current caching decisions say not to cache this field, FALSE is returned.
   If seq is 0, the existence isn't checked. */
bool mail_cache_field_want_add(struct mail_cache_transaction_ctx *ctx,
			       uint32_t seq, unsigned int field_idx);
/* Like mail_cache_field_want_add(), but in caching decisions FALSE is
   returned only if the decision is a forced no. */
bool mail_cache_field_can_add(struct mail_cache_transaction_ctx *ctx,
			      uint32_t seq, unsigned int field_idx);
/* Notify cache that the mail is now closed. Any records added with
   mail_cache_add() are unlikely to be required again. This mainly tells
   INDEX=MEMORY that it can free up the memory used by the mail. */
void mail_cache_close_mail(struct mail_cache_transaction_ctx *ctx,
			   uint32_t seq);

/* Returns 1 if field exists, 0 if not, -1 if error. */
int mail_cache_field_exists(struct mail_cache_view *view, uint32_t seq,
			    unsigned int field_idx);
/* Returns TRUE if something is cached for the message, FALSE if not. */
bool mail_cache_field_exists_any(struct mail_cache_view *view, uint32_t seq);
/* Returns current caching decision for given field. */
enum mail_cache_decision_type
mail_cache_field_get_decision(struct mail_cache *cache, unsigned int field_idx);
/* Notify the decision handling code when field is committed to cache.
   If this is the first time the field is added to cache, its caching decision
   is updated to TEMP. */
void mail_cache_decision_add(struct mail_cache_view *view, uint32_t seq,
			     unsigned int field);

/* Set data_r and size_r to point to wanted field in cache file.
   Returns 1 if field was found, 0 if not, -1 if error. */
int mail_cache_lookup_field(struct mail_cache_view *view, buffer_t *dest_buf,
			    uint32_t seq, unsigned int field_idx);

/* Return specified cached headers. Returns 1 if all fields were found,
   0 if not, -1 if error. dest is updated only if all fields were found. */
int mail_cache_lookup_headers(struct mail_cache_view *view, string_t *dest,
			      uint32_t seq, const unsigned int field_idxs[],
			      unsigned int fields_count);

/* "Error in index cache file %s: ...". */
void mail_cache_set_corrupted(struct mail_cache *cache, const char *fmt, ...)
	ATTR_FORMAT(2, 3);
void mail_cache_set_seq_corrupted_reason(struct mail_cache_view *cache_view,
					 uint32_t seq, const char *reason);

/* Returns human-readable reason for why a cached field is missing for
   the specified mail. This is mainly for debugging purposes, so the exact
   field doesn't matter here. */
const char *
mail_cache_get_missing_reason(struct mail_cache_view *view, uint32_t seq);

#endif
