/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hostpid.h"
#include "istream.h"
#include "istream-crlf.h"
#include "ostream.h"
#include "str.h"
#include "index-mail.h"
#include "cydir-storage.h"
#include "cydir-sync.h"

#include <stdio.h>
#include <utime.h>

struct cydir_save_context {
	struct mail_save_context ctx;

	struct cydir_mailbox *mbox;
	struct mail_index_transaction *trans;

	char *tmp_basename;
	unsigned int mail_count;

	struct cydir_sync_context *sync_ctx;

	/* updated for each appended mail: */
	uint32_t seq;
	struct istream *input;
	int fd;

	bool failed:1;
	bool finished:1;
};

#define CYDIR_SAVECTX(s)	container_of(s, struct cydir_save_context, ctx)

static char *cydir_generate_tmp_filename(void)
{
	static unsigned int create_count = 0;

	return i_strdup_printf("temp.%s.P%sQ%uM%s.%s",
			       dec2str(ioloop_timeval.tv_sec), my_pid,
			       create_count++,
			       dec2str(ioloop_timeval.tv_usec), my_hostname);
}

static const char *
cydir_get_save_path(struct cydir_save_context *ctx, unsigned int num)
{
	const char *dir;

	dir = mailbox_get_path(&ctx->mbox->box);
	return t_strdup_printf("%s/%s.%u", dir, ctx->tmp_basename, num);
}

struct mail_save_context *
cydir_save_alloc(struct mailbox_transaction_context *t)
{
	struct cydir_mailbox *mbox = CYDIR_MAILBOX(t->box);
	struct cydir_save_context *ctx;

	i_assert((t->flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	if (t->save_ctx == NULL) {
		ctx = i_new(struct cydir_save_context, 1);
		ctx->ctx.transaction = t;
		ctx->mbox = mbox;
		ctx->trans = t->itrans;
		ctx->tmp_basename = cydir_generate_tmp_filename();
		ctx->fd = -1;
		t->save_ctx = &ctx->ctx;
	}
	return t->save_ctx;
}

int cydir_save_begin(struct mail_save_context *_ctx, struct istream *input)
{
	struct cydir_save_context *ctx = CYDIR_SAVECTX(_ctx);
	struct mailbox_transaction_context *trans = _ctx->transaction;
	enum mail_flags save_flags;
	struct istream *crlf_input;

	ctx->failed = FALSE;

	T_BEGIN {
		const char *path;

		path = cydir_get_save_path(ctx, ctx->mail_count);
		ctx->fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0660);
		if (ctx->fd != -1) {
			_ctx->data.output =
				o_stream_create_fd_file(ctx->fd, 0, FALSE);
			o_stream_set_name(_ctx->data.output, path);
			o_stream_cork(_ctx->data.output);
		} else {
			mailbox_set_critical(trans->box, "open(%s) failed: %m",
					     path);
			ctx->failed = TRUE;
		}
	} T_END;
	if (ctx->failed)
		return -1;

	/* add to index */
	save_flags = _ctx->data.flags & ~MAIL_RECENT;
	mail_index_append(ctx->trans, 0, &ctx->seq);
	mail_index_update_flags(ctx->trans, ctx->seq, MODIFY_REPLACE,
				save_flags);
	if (_ctx->data.keywords != NULL) {
		mail_index_update_keywords(ctx->trans, ctx->seq,
					   MODIFY_REPLACE, _ctx->data.keywords);
	}
	if (_ctx->data.min_modseq != 0) {
		mail_index_update_modseq(ctx->trans, ctx->seq,
					 _ctx->data.min_modseq);
	}

	mail_set_seq_saving(_ctx->dest_mail, ctx->seq);

	crlf_input = i_stream_create_crlf(input);
	ctx->input = index_mail_cache_parse_init(_ctx->dest_mail, crlf_input);
	i_stream_unref(&crlf_input);
	return ctx->failed ? -1 : 0;
}

int cydir_save_continue(struct mail_save_context *_ctx)
{
	struct cydir_save_context *ctx = CYDIR_SAVECTX(_ctx);

	if (ctx->failed)
		return -1;

	if (index_storage_save_continue(_ctx, ctx->input,
					_ctx->dest_mail) < 0) {
		ctx->failed = TRUE;
		return -1;
	}
	return 0;
}

static int cydir_save_flush(struct cydir_save_context *ctx, const char *path)
{
	struct mail_storage *storage = &ctx->mbox->storage->storage;
	struct mailbox *box = &ctx->mbox->box;
	struct stat st;
	int ret = 0;

	if (o_stream_finish(ctx->ctx.data.output) < 0) {
		mailbox_set_critical(box, "write(%s) failed: %s", path,
			o_stream_get_error(ctx->ctx.data.output));
		ret = -1;
	}

	if (storage->set->parsed_fsync_mode != FSYNC_MODE_NEVER) {
		if (fsync(ctx->fd) < 0) {
			mailbox_set_critical(box, "fsync(%s) failed: %m", path);
			ret = -1;
		}
	}

	if (ctx->ctx.data.received_date == (time_t)-1) {
		if (fstat(ctx->fd, &st) == 0)
			ctx->ctx.data.received_date = st.st_mtime;
		else {
			mailbox_set_critical(box, "fstat(%s) failed: %m", path);
			ret = -1;
		}
	} else {
		struct utimbuf ut;

		ut.actime = ioloop_time;
		ut.modtime = ctx->ctx.data.received_date;
		if (utime(path, &ut) < 0) {
			mailbox_set_critical(box, "utime(%s) failed: %m", path);
			ret = -1;
		}
	}

	o_stream_destroy(&ctx->ctx.data.output);
	if (close(ctx->fd) < 0) {
		mailbox_set_critical(box, "close(%s) failed: %m", path);
		ret = -1;
	}
	ctx->fd = -1;
	return ret;
}

int cydir_save_finish(struct mail_save_context *_ctx)
{
	struct cydir_save_context *ctx = CYDIR_SAVECTX(_ctx);
	const char *path = cydir_get_save_path(ctx, ctx->mail_count);

	ctx->finished = TRUE;

	if (ctx->fd != -1) {
		if (cydir_save_flush(ctx, path) < 0)
			ctx->failed = TRUE;
	}

	if (!ctx->failed)
		ctx->mail_count++;
	else
		i_unlink(path);

	index_mail_cache_parse_deinit(_ctx->dest_mail,
				      _ctx->data.received_date, !ctx->failed);
	i_stream_unref(&ctx->input);

	index_save_context_free(_ctx);
	return ctx->failed ? -1 : 0;
}

void cydir_save_cancel(struct mail_save_context *_ctx)
{
	struct cydir_save_context *ctx = CYDIR_SAVECTX(_ctx);

	ctx->failed = TRUE;
	(void)cydir_save_finish(_ctx);
}

int cydir_transaction_save_commit_pre(struct mail_save_context *_ctx)
{
	struct cydir_save_context *ctx = CYDIR_SAVECTX(_ctx);
	struct mailbox_transaction_context *_t = _ctx->transaction;
	const struct mail_index_header *hdr;
	struct seq_range_iter iter;
	uint32_t uid;
	const char *dir;
	string_t *src_path, *dest_path;
	unsigned int n;
	size_t src_prefixlen, dest_prefixlen;

	i_assert(ctx->finished);

	if (cydir_sync_begin(ctx->mbox, &ctx->sync_ctx, TRUE) < 0) {
		ctx->failed = TRUE;
		cydir_transaction_save_rollback(_ctx);
		return -1;
	}

	hdr = mail_index_get_header(ctx->sync_ctx->sync_view);
	mail_index_append_finish_uids(ctx->trans, hdr->next_uid,
				      &_t->changes->saved_uids);
	_t->changes->uid_validity = ctx->sync_ctx->uid_validity;

	dir = mailbox_get_path(&ctx->mbox->box);

	src_path = t_str_new(256);
	str_printfa(src_path, "%s/%s.", dir, ctx->tmp_basename);
	src_prefixlen = str_len(src_path);

	dest_path = t_str_new(256);
	str_append(dest_path, dir);
	str_append_c(dest_path, '/');
	dest_prefixlen = str_len(dest_path);

	seq_range_array_iter_init(&iter, &_t->changes->saved_uids); n = 0;
	while (seq_range_array_iter_nth(&iter, n++, &uid)) {
		str_truncate(src_path, src_prefixlen);
		str_truncate(dest_path, dest_prefixlen);
		str_printfa(src_path, "%u", n-1);
		str_printfa(dest_path, "%u.", uid);

		if (rename(str_c(src_path), str_c(dest_path)) < 0) {
			mailbox_set_critical(&ctx->mbox->box,
				"rename(%s, %s) failed: %m",
				str_c(src_path), str_c(dest_path));
			ctx->failed = TRUE;
			cydir_transaction_save_rollback(_ctx);
			return -1;
		}
	}
	return 0;
}

void cydir_transaction_save_commit_post(struct mail_save_context *_ctx,
					struct mail_index_transaction_commit_result *result)
{
	struct cydir_save_context *ctx = CYDIR_SAVECTX(_ctx);

	_ctx->transaction = NULL; /* transaction is already freed */

	mail_index_sync_set_commit_result(ctx->sync_ctx->index_sync_ctx,
					  result);

	(void)cydir_sync_finish(&ctx->sync_ctx, TRUE);
	cydir_transaction_save_rollback(_ctx);
}

void cydir_transaction_save_rollback(struct mail_save_context *_ctx)
{
	struct cydir_save_context *ctx = CYDIR_SAVECTX(_ctx);

	if (!ctx->finished)
		cydir_save_cancel(&ctx->ctx);

	if (ctx->sync_ctx != NULL)
		(void)cydir_sync_finish(&ctx->sync_ctx, FALSE);

	i_free(ctx->tmp_basename);
	i_free(ctx);
}
