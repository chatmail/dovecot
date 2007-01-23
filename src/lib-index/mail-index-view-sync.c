/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"
#include "mail-transaction-log.h"
#include "mail-transaction-util.h"

struct mail_index_view_sync_ctx {
	struct mail_index_view *view;
	enum mail_transaction_type visible_sync_mask;
	struct mail_index_sync_map_ctx sync_map_ctx;
	array_t ARRAY_DEFINE(expunges, struct mail_transaction_expunge);

	const struct mail_transaction_header *hdr;
	const void *data;

	size_t data_offset;
	unsigned int skipped_some:1;
	unsigned int last_read:1;
	unsigned int sync_map_update:1;
};

struct mail_index_view_log_sync_pos {
	uint32_t log_file_seq;
	uoff_t log_file_offset;
};

static void
mail_transaction_log_sort_expunges(array_t *expunges,
				   const struct mail_transaction_expunge *src,
				   size_t src_size)
{
	ARRAY_SET_TYPE(expunges, struct mail_transaction_expunge);
	const struct mail_transaction_expunge *src_end;
	struct mail_transaction_expunge *dest;
	struct mail_transaction_expunge new_exp;
	unsigned int first, i, dest_count;

	i_assert(src_size % sizeof(*src) == 0);

	/* @UNSAFE */
	dest = array_get_modifyable(expunges, &dest_count);
	if (dest_count == 0) {
		array_append(expunges, src, src_size / sizeof(*src));
		return;
	}

	src_end = CONST_PTR_OFFSET(src, src_size);
	for (i = 0; src != src_end; src++) {
		/* src[] must be sorted. */
		i_assert(src+1 == src_end || src->uid2 < src[1].uid1);
		i_assert(src->uid1 <= src->uid2);

		for (; i < dest_count; i++) {
			if (src->uid1 < dest[i].uid1)
				break;
		}

		new_exp = *src;

		first = i;
		while (i < dest_count && src->uid2 >= dest[i].uid1-1) {
			/* we can/must merge with next record */
			if (new_exp.uid2 < dest[i].uid2)
				new_exp.uid2 = dest[i].uid2;
			i++;
		}

		if (first > 0 && new_exp.uid1 <= dest[first-1].uid2+1) {
			/* continue previous record */
			if (dest[first-1].uid2 < new_exp.uid2)
				dest[first-1].uid2 = new_exp.uid2;
		} else if (i == first) {
			array_insert(expunges, i, &new_exp, 1);
			i++; first++;

			dest = array_get_modifyable(expunges, &dest_count);
		} else {
			/* use next record */
			dest[first] = new_exp;
			first++;
		}

		if (i > first) {
			array_delete(expunges, first, i - first);

			dest = array_get_modifyable(expunges, &dest_count);
			i = first;
		}
	}
}

static int view_sync_set_log_view_range(struct mail_index_view *view,
					enum mail_transaction_type type_mask)
{
	const struct mail_index_header *hdr = view->index->hdr;
	int ret;

	ret = mail_transaction_log_view_set(view->log_view,
					    view->log_file_seq,
					    view->log_file_offset,
					    hdr->log_file_seq,
					    hdr->log_file_int_offset,
					    type_mask);
	if (ret <= 0) {
		if (ret == 0) {
			/* FIXME: use the new index to get needed changes */
			mail_index_set_error(view->index,
				"Transaction log got desynced for index %s",
				view->index->filepath);
			mail_index_set_inconsistent(view->index);
		}
		return -1;
	}
	return 0;
}

static int
view_sync_get_expunges(struct mail_index_view *view, array_t *expunges_r)
{
	ARRAY_SET_TYPE(expunges_r, struct mail_transaction_expunge);
	const struct mail_transaction_header *hdr;
	struct mail_transaction_expunge *src, *src_end, *dest;
	const void *data;
	unsigned int count;
	int ret;

	if (view_sync_set_log_view_range(view, MAIL_TRANSACTION_EXPUNGE) < 0)
		return -1;

	ARRAY_CREATE(expunges_r, default_pool,
		     struct mail_transaction_expunge, 64);
	while ((ret = mail_transaction_log_view_next(view->log_view,
						     &hdr, &data, NULL)) > 0) {
		i_assert((hdr->type & MAIL_TRANSACTION_EXPUNGE) != 0);
		mail_transaction_log_sort_expunges(expunges_r, data, hdr->size);
	}

	if (ret < 0) {
		array_free(expunges_r);
		return -1;
	}

	/* convert to sequences */
	src = dest = array_get_modifyable(expunges_r, &count);
	src_end = src + count;
	for (; src != src_end; src++) {
		ret = mail_index_lookup_uid_range(view, src->uid1,
						  src->uid2,
						  &dest->uid1,
						  &dest->uid2);
		i_assert(ret == 0);

		if (dest->uid1 == 0)
			count--;
		else
			dest++;
	}
	array_delete(expunges_r, count, array_count(expunges_r) - count);
	return 0;
}

static void mail_index_view_hdr_update(struct mail_index_view *view,
				       struct mail_index_map *map)
{
	/* Keep message count the same. */
	map->hdr.next_uid = view->hdr.next_uid;
	map->hdr.messages_count = view->hdr.messages_count;

	/* Keep the old message flag counts also, although they may be
	   somewhat stale already. We just don't want them to be more than
	   our old messages_count. */
	map->hdr.recent_messages_count = view->hdr.recent_messages_count;
	map->hdr.seen_messages_count = view->hdr.seen_messages_count;
	map->hdr.deleted_messages_count = view->hdr.deleted_messages_count;

	/* Keep log position so we know where to continue syncing */
	map->hdr.log_file_seq = view->hdr.log_file_seq;
	map->hdr.log_file_int_offset = view->hdr.log_file_int_offset;
	map->hdr.log_file_ext_offset = view->hdr.log_file_ext_offset;

	view->hdr = map->hdr;
	buffer_write(map->hdr_copy_buf, 0, &map->hdr, sizeof(map->hdr));
}

#define MAIL_INDEX_VIEW_VISIBLE_FLAGS_MASK \
	(MAIL_INDEX_SYNC_TYPE_FLAGS | \
	 MAIL_INDEX_SYNC_TYPE_KEYWORD_RESET | \
	 MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD | MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE)

#define MAIL_TRANSACTION_VISIBLE_SYNC_MASK \
	(MAIL_TRANSACTION_EXPUNGE | MAIL_TRANSACTION_APPEND | \
	 MAIL_TRANSACTION_FLAG_UPDATE | MAIL_TRANSACTION_KEYWORD_UPDATE | \
	 MAIL_TRANSACTION_KEYWORD_RESET)

#ifdef DEBUG
static void mail_index_view_check(struct mail_index_view *view)
{
	unsigned int i, del = 0, recent = 0, seen = 0;

	i_assert(view->hdr.deleted_messages_count ==
		 view->map->hdr.deleted_messages_count);
	i_assert(view->hdr.recent_messages_count ==
		 view->map->hdr.recent_messages_count);
	i_assert(view->hdr.seen_messages_count ==
		 view->map->hdr.seen_messages_count);

	for (i = 0; i < view->map->records_count; i++) {
		const struct mail_index_record *rec;

		rec = MAIL_INDEX_MAP_IDX(view->map, i);

		if (rec->flags & MAIL_DELETED) {
			i_assert(rec->uid >= view->hdr.first_deleted_uid_lowwater);
			del++;
		}
		if (rec->flags & MAIL_RECENT) {
			i_assert(rec->uid >= view->hdr.first_recent_uid_lowwater);
			recent++;
		}
		if (rec->flags & MAIL_SEEN)
			seen++;
		else
			i_assert(rec->uid >= view->hdr.first_unseen_uid_lowwater);
	}
	i_assert(del == view->hdr.deleted_messages_count);
	i_assert(recent == view->hdr.recent_messages_count);
	i_assert(seen == view->hdr.seen_messages_count);
}
#endif

int mail_index_view_sync_begin(struct mail_index_view *view,
                               enum mail_index_sync_type sync_mask,
			       struct mail_index_view_sync_ctx **ctx_r)
{
	struct mail_index_view_sync_ctx *ctx;
	struct mail_index_map *map;
	enum mail_transaction_type log_get_mask, visible_mask;
	array_t expunges = { 0, 0 };

	/* We must sync flags as long as view is mmap()ed, as the flags may
	   have already changed under us. */
	i_assert((sync_mask & MAIL_INDEX_VIEW_VISIBLE_FLAGS_MASK) ==
		 MAIL_INDEX_VIEW_VISIBLE_FLAGS_MASK);
	/* Currently we're not handling correctly expunges + no-appends case */
	i_assert((sync_mask & MAIL_INDEX_SYNC_TYPE_EXPUNGE) == 0 ||
		 (sync_mask & MAIL_INDEX_SYNC_TYPE_APPEND) != 0);

	i_assert(!view->syncing);
	i_assert(view->transactions == 0);

	if (mail_index_view_lock_head(view, TRUE) < 0)
		return -1;

	if ((sync_mask & MAIL_INDEX_SYNC_TYPE_EXPUNGE) != 0) {
		/* get list of all expunges first */
		if (view_sync_get_expunges(view, &expunges) < 0)
			return -1;
	}

	/* only flags, appends and expunges can be left to be synced later */
	visible_mask = mail_transaction_type_mask_get(sync_mask);
	i_assert((visible_mask & ~MAIL_TRANSACTION_VISIBLE_SYNC_MASK) == 0);

	/* we want to also get non-visible changes. especially because we use
	   the returned skipped-flag in mail_transaction_log_view_next() to
	   tell us if any visible changes were skipped. */
	log_get_mask = visible_mask | (MAIL_TRANSACTION_TYPE_MASK ^
				       MAIL_TRANSACTION_VISIBLE_SYNC_MASK);
	if (view_sync_set_log_view_range(view, log_get_mask) < 0) {
		if (array_is_created(&expunges))
			array_free(&expunges);
		return -1;
	}

	ctx = i_new(struct mail_index_view_sync_ctx, 1);
	ctx->view = view;
	ctx->visible_sync_mask = visible_mask;
	ctx->expunges = expunges;
	mail_index_sync_map_init(&ctx->sync_map_ctx, view,
				 MAIL_INDEX_SYNC_HANDLER_VIEW);

	if ((sync_mask & MAIL_INDEX_SYNC_TYPE_EXPUNGE) != 0 &&
	    (sync_mask & MAIL_INDEX_SYNC_TYPE_APPEND) != 0) {
		view->sync_new_map = view->index->map;
		view->sync_new_map->refcount++;

		/* since we're syncing everything, the counters get fixed */
		view->broken_counters = FALSE;

		/* keep the old mapping without expunges until we're
		   fully synced */
	} else {
		/* We need a private copy of the map if we don't want to
		   sync expunges.

		   If view's map is the head map, it means that it contains
		   already all the latest changes and there's no need for us
		   to apply any changes to it. This can only happen if there
		   hadn't been any expunges. */
		uint32_t old_records_count = view->map->records_count;

		if (view->map != view->index->map) {
			const struct mail_index_header *hdr;

			/* Using non-head mapping. We have to apply
			   transactions to it to get latest changes into it. */
			ctx->sync_map_update = TRUE;

			/* Unless map was synced at the exact same position as
			   view, the message flags can't be reliably used to
			   update flag counters. note that map->hdr may contain
			   old information if another process updated the
			   index file since. */
			if (view->map->mmap_base == NULL)
				hdr = &view->map->hdr;
			else {
				hdr = view->map->mmap_base;
				view->map->hdr = *hdr;
			}
			ctx->sync_map_ctx.unreliable_flags =
				!(hdr->log_file_seq == view->log_file_seq &&
				  hdr->log_file_int_offset ==
				  view->log_file_offset);

			/* Copy only the mails that we see currently, since
			   we're going to append the new ones when we see
			   their transactions. */
			i_assert(view->map->records_count >=
				 view->hdr.messages_count);
			view->map->records_count = view->hdr.messages_count;

#ifdef DEBUG
			if (!ctx->sync_map_ctx.unreliable_flags)
				mail_index_view_check(view);
#endif
		}

		map = mail_index_map_clone(view->map,
					   view->map->hdr.record_size);
		view->map->records_count = old_records_count;
		mail_index_unmap(view->index, &view->map);
		view->map = map;

		if (ctx->sync_map_update) {
			/* Start the sync using our old view's header.
			   The old view->hdr may differ from map->hdr if
			   another view sharing the map with us had synced
			   itself. */
			i_assert(map->hdr_base == map->hdr_copy_buf->data);
			mail_index_view_hdr_update(view, map);
		}

		i_assert(map->records_count == map->hdr.messages_count);
	}

	/* Syncing the view invalidates all previous looked up records.
	   Unreference the mappings this view keeps because of them. */
	mail_index_view_unref_maps(view);
	view->syncing = TRUE;

	*ctx_r = ctx;
	return 0;
}

static bool view_sync_pos_find(array_t *sync_arr, uint32_t seq, uoff_t offset)
{
	ARRAY_SET_TYPE(sync_arr, struct mail_index_view_log_sync_pos);
	const struct mail_index_view_log_sync_pos *syncs;
	unsigned int i, count;

	if (!array_is_created(sync_arr))
		return FALSE;

	syncs = array_get(sync_arr, &count);
	for (i = 0; i < count; i++) {
		if (syncs[i].log_file_offset == offset &&
		    syncs[i].log_file_seq == seq)
			return TRUE;
	}

	return FALSE;
}

static int
mail_index_view_sync_get_next_transaction(struct mail_index_view_sync_ctx *ctx)
{
        struct mail_transaction_log_view *log_view = ctx->view->log_view;
	struct mail_index_view *view = ctx->view;
	uint32_t seq;
	uoff_t offset;
	int ret;
	bool skipped, synced_to_map;

	for (;;) {
		/* Get the next transaction from log. */
		ret = mail_transaction_log_view_next(log_view, &ctx->hdr,
						     &ctx->data, &skipped);

		if (skipped) {
			/* We skipped some (visible) transactions that were
			   outside our sync mask. Note that we may get here
			   even when ret=0. */
			ctx->skipped_some = TRUE;
		}

		if (ret <= 0) {
			if (ret < 0)
				return -1;

			ctx->hdr = NULL;
			ctx->last_read = TRUE;
			return 0;
		}

		mail_transaction_log_view_get_prev_pos(log_view, &seq, &offset);

		if (!ctx->skipped_some) {
			/* We haven't skipped anything while syncing this view.
			   Update this view's synced log offset. */
			view->log_file_seq = seq;
			view->log_file_offset = offset + sizeof(*ctx->hdr) +
				ctx->hdr->size;
		}

		/* skip everything we've already synced */
		if (view_sync_pos_find(&view->syncs_done, seq, offset))
			continue;

		if (ctx->skipped_some) {
			/* We've been skipping some transactions, which means
			   we'll go through these same transactions again
			   later. Since we're syncing this one, we don't want
			   to do it again. */
			mail_index_view_add_synced_transaction(view, seq,
							       offset);
		}

		/* view->log_file_offset contains the minimum of
		   int/ext offsets. */
		synced_to_map = offset < view->hdr.log_file_ext_offset &&
			seq == view->hdr.log_file_seq &&
			(ctx->hdr->type & MAIL_TRANSACTION_EXTERNAL) != 0;

		/* Apply transaction to view's mapping if needed (meaning we
		   didn't just re-map the view to head mapping). */
		if (ctx->sync_map_update && !synced_to_map) {
			i_assert((ctx->hdr->type &
				  MAIL_TRANSACTION_EXPUNGE) == 0);

			if (mail_index_sync_record(&ctx->sync_map_ctx,
						   ctx->hdr, ctx->data) < 0)
				return -1;
		}

		if ((ctx->hdr->type & ctx->visible_sync_mask) == 0) {
			/* non-visible change that we just wanted to update
			   to map. */
			continue;
		}

		/* skip changes committed by hidden transactions (eg. in IMAP
		   store +flags.silent command) */
		if (view_sync_pos_find(&view->syncs_hidden, seq, offset))
			continue;
		break;
	}
	return 1;
}

#define FLAG_UPDATE_IS_INTERNAL(u) \
	((((u)->add_flags | (u)->remove_flags) & \
	  ~(MAIL_INDEX_MAIL_FLAG_DIRTY | MAIL_RECENT)) == 0)

static int
mail_index_view_sync_get_rec(struct mail_index_view_sync_ctx *ctx,
			     struct mail_index_view_sync_rec *rec)
{
	const struct mail_transaction_header *hdr = ctx->hdr;
	const void *data = ctx->data;

	switch (hdr->type & MAIL_TRANSACTION_TYPE_MASK) {
	case MAIL_TRANSACTION_APPEND: {
		/* data contains the appended records, but we don't care */
		rec->type = MAIL_INDEX_SYNC_TYPE_APPEND;
		rec->uid1 = rec->uid2 = 0;
		ctx->data_offset += hdr->size;
		break;
	}
	case MAIL_TRANSACTION_EXPUNGE: {
		const struct mail_transaction_expunge *exp =
			CONST_PTR_OFFSET(data, ctx->data_offset);

		/* data contains mail_transaction_expunge[] */
		rec->type = MAIL_INDEX_SYNC_TYPE_EXPUNGE;
		rec->uid1 = exp->uid1;
		rec->uid2 = exp->uid2;

		ctx->data_offset += sizeof(*exp);
		break;
	}
	case MAIL_TRANSACTION_FLAG_UPDATE: {
		const struct mail_transaction_flag_update *update =
			CONST_PTR_OFFSET(data, ctx->data_offset);

		/* data contains mail_transaction_flag_update[] */
		for (;;) {
			ctx->data_offset += sizeof(*update);
			if (!FLAG_UPDATE_IS_INTERNAL(update))
				break;

			/* skip internal flag changes */
			if (ctx->data_offset == ctx->hdr->size)
				return 0;

			update = CONST_PTR_OFFSET(data, ctx->data_offset);
		}

		rec->type = MAIL_INDEX_SYNC_TYPE_FLAGS;
		rec->uid1 = update->uid1;
		rec->uid2 = update->uid2;
		break;
	}
	case MAIL_TRANSACTION_KEYWORD_UPDATE: {
		const struct mail_transaction_keyword_update *update = data;
		const uint32_t *uids;

		/* data contains mail_transaction_keyword_update header,
		   the keyword name and an array of { uint32_t uid1, uid2; } */

		if (ctx->data_offset == 0) {
			/* skip over the header and name */
			ctx->data_offset = sizeof(*update) + update->name_size;
			if ((ctx->data_offset % 4) != 0)
				ctx->data_offset += 4 - (ctx->data_offset % 4);
		}

		uids = CONST_PTR_OFFSET(data, ctx->data_offset);
		rec->type = MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD;
		rec->uid1 = uids[0];
		rec->uid2 = uids[1];

		ctx->data_offset += sizeof(uint32_t) * 2;
		break;
	}
	case MAIL_TRANSACTION_KEYWORD_RESET: {
		const struct mail_transaction_keyword_reset *reset =
			CONST_PTR_OFFSET(data, ctx->data_offset);

		/* data contains mail_transaction_keyword_reset[] */
		rec->type = MAIL_INDEX_SYNC_TYPE_KEYWORD_RESET;
		rec->uid1 = reset->uid1;
		rec->uid2 = reset->uid2;
		ctx->data_offset += sizeof(*reset);
		break;
	}
	default:
		i_unreached();
	}
	return 1;
}

int mail_index_view_sync_next(struct mail_index_view_sync_ctx *ctx,
			      struct mail_index_view_sync_rec *sync_rec)
{
	int ret;

	do {
		if (ctx->hdr == NULL || ctx->data_offset == ctx->hdr->size) {
			ret = mail_index_view_sync_get_next_transaction(ctx);
			if (ret <= 0)
				return ret;

			ctx->data_offset = 0;
		}
	} while (!mail_index_view_sync_get_rec(ctx, sync_rec));

	return 1;
}

const array_t *
mail_index_view_sync_get_expunges(struct mail_index_view_sync_ctx *ctx)
{
	return &ctx->expunges;
}

static void
mail_index_view_sync_clean_log_syncs(struct mail_index_view_sync_ctx *ctx,
				     array_t *sync_arr)
{
	ARRAY_SET_TYPE(sync_arr, struct mail_index_view_log_sync_pos);
	struct mail_index_view *view = ctx->view;
	const struct mail_index_view_log_sync_pos *syncs;
	unsigned int i, count;

	if (!array_is_created(sync_arr))
		return;

	if (!ctx->skipped_some) {
		/* Nothing skipped. Clean it up the quick way. */
		array_clear(sync_arr);
		return;
	}

	/* Clean up until view's current syncing position */
	syncs = array_get(sync_arr, &count);
	for (i = 0; i < count; i++) {
		if ((syncs[i].log_file_offset >= view->log_file_offset &&
                     syncs[i].log_file_seq == view->log_file_seq) ||
		    syncs[i].log_file_seq > view->log_file_seq)
			break;
	}
	if (i > 0)
		array_delete(sync_arr, 0, i);
}

void mail_index_view_sync_end(struct mail_index_view_sync_ctx **_ctx)
{
        struct mail_index_view_sync_ctx *ctx = *_ctx;
        struct mail_index_view *view = ctx->view;

	i_assert(view->syncing);

	*_ctx = NULL;
	mail_index_sync_map_deinit(&ctx->sync_map_ctx);
	mail_index_view_sync_clean_log_syncs(ctx, &view->syncs_done);
	mail_index_view_sync_clean_log_syncs(ctx, &view->syncs_hidden);

	if (!ctx->last_read && ctx->hdr != NULL &&
	    ctx->data_offset != ctx->hdr->size) {
		/* we didn't sync everything */
		view->inconsistent = TRUE;
	}

	if (view->sync_new_map != NULL) {
		mail_index_unmap(view->index, &view->map);
		view->map = view->sync_new_map;
		view->sync_new_map = NULL;
	}
	view->hdr = view->map->hdr;

#ifdef DEBUG
	if (!view->broken_counters)
		mail_index_view_check(view);
#endif

	/* set log view to empty range so unneeded memory gets freed */
	(void)mail_transaction_log_view_set(view->log_view,
					    view->log_file_seq,
					    view->log_file_offset,
					    view->log_file_seq,
					    view->log_file_offset,
					    MAIL_TRANSACTION_TYPE_MASK);

	if (array_is_created(&ctx->expunges))
		array_free(&ctx->expunges);

	view->syncing = FALSE;
	i_free(ctx);
}

static void log_sync_pos_add(array_t *sync_arr, uint32_t log_file_seq,
			     uoff_t log_file_offset)
{
	ARRAY_SET_TYPE(sync_arr, struct mail_index_view_log_sync_pos);
	struct mail_index_view_log_sync_pos *pos;

	if (!array_is_created(sync_arr)) {
		ARRAY_CREATE(sync_arr, default_pool,
                             struct mail_index_view_log_sync_pos, 32);
	}

	pos = array_append_space(sync_arr);
	pos->log_file_seq = log_file_seq;
	pos->log_file_offset = log_file_offset;
}

void mail_index_view_add_synced_transaction(struct mail_index_view *view,
					    uint32_t log_file_seq,
					    uoff_t log_file_offset)
{
	log_sync_pos_add(&view->syncs_done, log_file_seq, log_file_offset);
}

void mail_index_view_add_hidden_transaction(struct mail_index_view *view,
					    uint32_t log_file_seq,
					    uoff_t log_file_offset)
{
	log_sync_pos_add(&view->syncs_hidden, log_file_seq, log_file_offset);
}
