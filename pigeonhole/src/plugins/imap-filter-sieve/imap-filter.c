/* Copyright (c) 2017-2018 Pigeonhole authors, see the included COPYING file */

#include "imap-common.h"
#include "str.h"
#include "ostream.h"
#include "imap-resp-code.h"
#include "imap-search-args.h"

#include "imap-filter.h"
#include "imap-filter-sieve.h"

static void imap_filter_args_check(struct imap_filter_context *ctx,
				   const struct mail_search_arg *sargs)
{
	for (; sargs != NULL; sargs = sargs->next) {
		switch (sargs->type) {
		case SEARCH_SEQSET:
			ctx->have_seqsets = TRUE;
			break;
		case SEARCH_MODSEQ:
			ctx->have_modseqs = TRUE;
			break;
		case SEARCH_OR:
		case SEARCH_SUB:
			imap_filter_args_check(ctx, sargs->value.subargs);
			break;
		default:
			break;
		}
	}
}

static bool
imap_filter_mail(struct client_command_context *cmd, struct mail *mail)
{
	struct imap_filter_context *ctx = cmd->context;
	struct client *client = cmd->client;
	string_t *errors = NULL;
	bool have_warnings = FALSE;
	int ret;

	// FIXME: return fatal error status when no mail filter activity will
	// work (e.g. when binary is corrupt)
	ret = imap_sieve_filter_run_mail(ctx->sieve, mail,
					 &errors, &have_warnings);

	o_stream_nsend_str(client->output,
		t_strdup_printf("* %u FILTERED (TAG %s) UID %u ",
				mail->seq, cmd->tag, mail->uid));
	if (ret < 0 || have_warnings) {
		o_stream_nsend_str(client->output,
			t_strdup_printf("%s {%"PRIuSIZE_T"}\r\n",
					(ret < 0 ? "ERRORS" : "WARNINGS"),
					str_len(errors)));
		o_stream_nsend(client->output,
			       str_data(errors), str_len(errors));
		o_stream_nsend_str(client->output, "\r\n");
	} else {
		o_stream_nsend_str(client->output, "OK\r\n");
	}

	/* Handle the result */
	if (ret < 0) {
		/* Sieve error; keep */
	} else {
		if (ret > 0) {
			/* Discard */
			mail_update_flags(mail, MODIFY_ADD, MAIL_DELETED);
		}
	}

	return TRUE;
}

static bool imap_filter_more(struct client_command_context *cmd)
{
	struct imap_filter_context *ctx = cmd->context;
	struct mail *mail;
	enum mailbox_sync_flags sync_flags;
	const char *ok_reply;
	bool tryagain, lost_data;

	if (cmd->cancel) {
		(void)imap_filter_deinit(ctx);
		return TRUE;
	}

	while (mailbox_search_next_nonblock(ctx->search_ctx,
					    &mail, &tryagain)) {
		if (!imap_filter_mail(cmd, mail))
			break;
	}
	if (tryagain)
		return FALSE;

	lost_data = mailbox_search_seen_lost_data(ctx->search_ctx);
	if (imap_filter_deinit(ctx) < 0) {
		client_send_box_error(cmd, cmd->client->mailbox);
		return TRUE;
	}

	sync_flags = MAILBOX_SYNC_FLAG_FAST;
	if (!cmd->uid || ctx->have_seqsets)
		sync_flags |= MAILBOX_SYNC_FLAG_NO_EXPUNGES;
	ok_reply = t_strdup_printf("OK %sFilter completed",
		lost_data ? "["IMAP_RESP_CODE_EXPUNGEISSUED"] " : "");
	return cmd_sync(cmd, sync_flags, 0, ok_reply);
}

static void imap_filter_more_callback(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	bool finished;

	o_stream_cork(client->output);
	finished = command_exec(cmd);
	o_stream_uncork(client->output);

	if (!finished)
		(void)client_handle_unfinished_cmd(cmd);
	else
		client_command_free(&cmd);
	cmd_sync_delayed(client);

	if (client->disconnected)
		client_destroy(client, NULL);
	else
		client_continue_pending_input(client);
}

static bool
imap_filter_start(struct imap_filter_context *ctx,
		  struct mail_search_args *sargs)
{
	struct client_command_context *cmd = ctx->cmd;

	imap_filter_args_check(ctx, sargs->args);

	if (ctx->have_modseqs)
		(void)client_enable(cmd->client, MAILBOX_FEATURE_CONDSTORE);

	ctx->box = cmd->client->mailbox;
	ctx->trans = mailbox_transaction_begin(ctx->box, 0);
	ctx->sargs = sargs;
	ctx->search_ctx = mailbox_search_init(ctx->trans, sargs, NULL, 0, NULL);

	cmd->func = imap_filter_more;
	cmd->context = ctx;

	if (imap_filter_more(cmd))
		return TRUE;

	/* we may have moved onto syncing by now */
	if (cmd->func == imap_filter_more) {
		ctx->to = timeout_add(0, imap_filter_more_callback, cmd);
		cmd->state = CLIENT_COMMAND_STATE_WAIT_EXTERNAL;
	}
	return FALSE;
}

static bool
imap_filter_parse_search(struct imap_filter_context *ctx,
			const struct imap_arg *args)
{
	struct client_command_context *cmd = ctx->cmd;
	struct mail_search_args *sargs;
	const char *charset;
	int ret;

	if (imap_arg_atom_equals(args, "CHARSET")) {
		/* CHARSET specified */
		if (!imap_arg_get_astring(&args[1], &charset)) {
			client_send_command_error(cmd,
				"Invalid charset argument.");
			imap_filter_context_free(ctx);
			return TRUE;
		}
		args += 2;
	} else {
		charset = "UTF-8";
	}

	ret = imap_search_args_build(cmd, args, charset, &sargs);
	if (ret <= 0) {
		imap_filter_context_free(ctx);
		return ret < 0;
	}

	return imap_filter_start(ctx, sargs);
}

bool imap_filter_search(struct client_command_context *cmd)
{
	struct imap_filter_context *ctx = cmd->context;
	const struct imap_arg *args;
	const char *error;
	bool fatal;
	int ret;

	ret = imap_parser_read_args(ctx->parser, 0, 0, &args);
	if (ret < 0) {
		if (ret == -2)
			return FALSE;
		error = imap_parser_get_error(ctx->parser, &fatal);
		if (fatal) {
			client_disconnect_with_error(ctx->cmd->client, error);
			return TRUE;
		}
		client_send_command_error(ctx->cmd, error);
		return TRUE;
	}
	return imap_filter_parse_search(ctx, args);
}

int imap_filter_deinit(struct imap_filter_context *ctx)
{
	int ret = 0;

	o_stream_set_flush_callback(ctx->cmd->client->output,
				    client_output, ctx->cmd->client);
	ctx->cmd->client->input_lock = NULL;
	imap_parser_unref(&ctx->parser);

	if (ctx->search_ctx != NULL &&
	    mailbox_search_deinit(&ctx->search_ctx) < 0)
		ret = -1;

	if (ctx->trans != NULL)
		(void)mailbox_transaction_commit(&ctx->trans);

	if (ctx->to != NULL)
		timeout_remove(&ctx->to);
	if (ctx->sargs != NULL) {
		mail_search_args_deinit(ctx->sargs);
		mail_search_args_unref(&ctx->sargs);
	}
	imap_filter_context_free(ctx);

	ctx->cmd->context = NULL;
	return ret;
}

void imap_filter_context_free(struct imap_filter_context *ctx)
{
	imap_filter_sieve_context_free(&ctx->sieve);
}



