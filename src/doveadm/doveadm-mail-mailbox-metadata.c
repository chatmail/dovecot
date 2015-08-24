/* Copyright (c) 2014-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "doveadm-print.h"
#include "doveadm-mail.h"
#include "doveadm-mailbox-list-iter.h"

struct metadata_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	const char *mailbox;
	enum mail_attribute_type key_type;
	const char *key;
	struct mail_attribute_value value;
};

static int
cmd_mailbox_metadata_set_run(struct doveadm_mail_cmd_context *_ctx,
			     struct mail_user *user)
{
	struct metadata_cmd_context *ctx = (struct metadata_cmd_context *)_ctx;
	struct mail_namespace *ns;
	struct mailbox *box;
	struct mailbox_transaction_context *trans;
	int ret;

	ns = mail_namespace_find(user->namespaces, ctx->mailbox);
	box = mailbox_alloc(ns->list, ctx->mailbox, 0);

	if (mailbox_open(box) < 0) {
		i_error("Failed to open mailbox: %s",
			mailbox_get_last_error(box, NULL));
		doveadm_mail_failed_mailbox(_ctx, box);
		mailbox_free(&box);
		return -1;
	}
	trans = mailbox_transaction_begin(box, 0);

	ret = ctx->value.value == NULL ?
		mailbox_attribute_unset(trans, ctx->key_type, ctx->key) :
		mailbox_attribute_set(trans, ctx->key_type, ctx->key, &ctx->value);
	if (ret < 0) {
		i_error("Failed to set attribute: %s",
			mailbox_get_last_error(box, NULL));
		doveadm_mail_failed_mailbox(_ctx, box);
		mailbox_transaction_rollback(&trans);
	} else if (mailbox_transaction_commit(&trans) < 0) {
		i_error("Failed to commit transaction: %s",
			mailbox_get_last_error(box, NULL));
		doveadm_mail_failed_mailbox(_ctx, box);
		ret = -1;
	}

	mailbox_free(&box);
	return ret;
}

static void
cmd_mailbox_metadata_parse_key(const char *arg,
			       enum mail_attribute_type *type_r,
			       const char **key_r)
{
	if (strncmp(arg, "/private/", 9) == 0) {
		*type_r = MAIL_ATTRIBUTE_TYPE_PRIVATE;
		*key_r = arg + 9;
	} else if (strncmp(arg, "/shared/", 8) == 0) {
		*type_r = MAIL_ATTRIBUTE_TYPE_SHARED;
		*key_r = arg + 8;
	} else if (strcmp(arg, "/private") == 0) {
		*type_r = MAIL_ATTRIBUTE_TYPE_PRIVATE;
		*key_r = "";
	} else if (strcmp(arg, "/shared") == 0) {
		*type_r = MAIL_ATTRIBUTE_TYPE_SHARED;
		*key_r = "";
	} else {
		i_fatal_status(EX_USAGE, "Invalid metadata key '%s': "
			       "Must begin with /private or /shared", arg);
	}
	*key_r = t_str_lcase(*key_r);
}

static void
cmd_mailbox_metadata_set_init(struct doveadm_mail_cmd_context *_ctx,
			      const char *const args[])
{
	struct metadata_cmd_context *ctx = (struct metadata_cmd_context *)_ctx;
	const char *key;

	if (str_array_length(args) != 3)
		doveadm_mail_help_name("mailbox metadata set");
	cmd_mailbox_metadata_parse_key(args[1], &ctx->key_type, &key);

	ctx->mailbox = p_strdup(_ctx->pool, args[0]);
	ctx->key = p_strdup(_ctx->pool, key);
	ctx->value.value = p_strdup(_ctx->pool, args[2]);
}

static struct doveadm_mail_cmd_context *cmd_mailbox_metadata_set_alloc(void)
{
	struct metadata_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct metadata_cmd_context);
	ctx->ctx.v.init = cmd_mailbox_metadata_set_init;
	ctx->ctx.v.run = cmd_mailbox_metadata_set_run;
	return &ctx->ctx;
}

static void
cmd_mailbox_metadata_unset_init(struct doveadm_mail_cmd_context *_ctx,
				const char *const args[])
{
	struct metadata_cmd_context *ctx = (struct metadata_cmd_context *)_ctx;
	const char *key;

	if (str_array_length(args) != 2)
		doveadm_mail_help_name("mailbox metadata unset");
	cmd_mailbox_metadata_parse_key(args[1], &ctx->key_type, &key);

	ctx->mailbox = p_strdup(_ctx->pool, args[0]);
	ctx->key = p_strdup(_ctx->pool, key);
}

static struct doveadm_mail_cmd_context *cmd_mailbox_metadata_unset_alloc(void)
{
	struct metadata_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct metadata_cmd_context);
	ctx->ctx.v.init = cmd_mailbox_metadata_unset_init;
	ctx->ctx.v.run = cmd_mailbox_metadata_set_run;
	return &ctx->ctx;
}

static int
cmd_mailbox_metadata_get_run(struct doveadm_mail_cmd_context *_ctx,
			     struct mail_user *user)
{
	struct metadata_cmd_context *ctx = (struct metadata_cmd_context *)_ctx;
	struct mail_namespace *ns;
	struct mailbox *box;
	struct mailbox_transaction_context *trans;
	struct mail_attribute_value value;
	int ret;

	ns = mail_namespace_find(user->namespaces, ctx->mailbox);
	box = mailbox_alloc(ns->list, ctx->mailbox, 0);

	if (mailbox_open(box) < 0) {
		i_error("Failed to open mailbox: %s",
			mailbox_get_last_error(box, NULL));
		doveadm_mail_failed_mailbox(_ctx, box);
		mailbox_free(&box);
		return -1;
	}
	trans = mailbox_transaction_begin(box, 0);

	ret = mailbox_attribute_get_stream(trans, ctx->key_type, ctx->key, &value);
	if (ret < 0) {
		i_error("Failed to get attribute: %s",
			mailbox_get_last_error(box, NULL));
		doveadm_mail_failed_mailbox(_ctx, box);
	} else if (ret == 0) {
		/* not found, print as empty */
		doveadm_print("");
	} else if (value.value_stream != NULL) {
		doveadm_print_istream(value.value_stream);
	} else {
		doveadm_print(value.value);
	}

	(void)mailbox_transaction_commit(&trans);
	mailbox_free(&box);
	return ret;
}

static void
cmd_mailbox_metadata_get_init(struct doveadm_mail_cmd_context *_ctx,
			      const char *const args[])
{
	struct metadata_cmd_context *ctx = (struct metadata_cmd_context *)_ctx;
	const char *key;

	if (str_array_length(args) != 2)
		doveadm_mail_help_name("mailbox metadata get");
	cmd_mailbox_metadata_parse_key(args[1], &ctx->key_type, &key);

	ctx->mailbox = p_strdup(_ctx->pool, args[0]);
	ctx->key = p_strdup(_ctx->pool, key);
	doveadm_print_header("value", "value",
			     DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
}

static struct doveadm_mail_cmd_context *cmd_mailbox_metadata_get_alloc(void)
{
	struct metadata_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct metadata_cmd_context);
	ctx->ctx.v.init = cmd_mailbox_metadata_get_init;
	ctx->ctx.v.run = cmd_mailbox_metadata_get_run;
	doveadm_print_init(DOVEADM_PRINT_TYPE_FLOW);
	return &ctx->ctx;
}

static int
cmd_mailbox_metadata_list_run_iter(struct metadata_cmd_context *ctx,
				   struct mailbox *box,
				   enum mail_attribute_type type)
{
	struct mailbox_attribute_iter *iter;
	const char *key;

	iter = mailbox_attribute_iter_init(box, type, ctx->key);
	while ((key = mailbox_attribute_iter_next(iter)) != NULL)
		doveadm_print(key);
	if (mailbox_attribute_iter_deinit(&iter) < 0) {
		i_error("Mailbox %s: Failed to iterate mailbox attributes: %s",
			mailbox_get_vname(box),
			mailbox_get_last_error(box, NULL));
		return -1;
	}
	return 0;
}

static int
cmd_mailbox_metadata_list_run(struct doveadm_mail_cmd_context *_ctx,
			      struct mail_user *user)
{
	struct metadata_cmd_context *ctx = (struct metadata_cmd_context *)_ctx;
	struct mail_namespace *ns;
	struct mailbox *box;
	int ret = 0;

	ns = mail_namespace_find(user->namespaces, ctx->mailbox);
	box = mailbox_alloc(ns->list, ctx->mailbox, 0);

	if (mailbox_open(box) < 0) {
		i_error("Failed to open mailbox: %s",
			mailbox_get_last_error(box, NULL));
		doveadm_mail_failed_mailbox(_ctx, box);
		mailbox_free(&box);
		return -1;
	}

	if (ctx->key == NULL || ctx->key_type == MAIL_ATTRIBUTE_TYPE_PRIVATE) {
		if (cmd_mailbox_metadata_list_run_iter(ctx, box, MAIL_ATTRIBUTE_TYPE_PRIVATE) < 0) {
			doveadm_mail_failed_mailbox(_ctx, box);
			ret = -1;
		}
	}
	if (ctx->key == NULL || ctx->key_type == MAIL_ATTRIBUTE_TYPE_SHARED) {
		if (cmd_mailbox_metadata_list_run_iter(ctx, box, MAIL_ATTRIBUTE_TYPE_SHARED) < 0) {
			doveadm_mail_failed_mailbox(_ctx, box);
			ret = -1;
		}
	}
	mailbox_free(&box);
	return ret;
}

static void
cmd_mailbox_metadata_list_init(struct doveadm_mail_cmd_context *_ctx,
			       const char *const args[])
{
	struct metadata_cmd_context *ctx = (struct metadata_cmd_context *)_ctx;
	const char *key;

	if (args[0] == NULL)
		doveadm_mail_help_name("mailbox metadata list");
	if (args[1] != NULL)
		cmd_mailbox_metadata_parse_key(args[1], &ctx->key_type, &key);
	ctx->mailbox = p_strdup(_ctx->pool, args[0]);
	doveadm_print_header("key", "key",
			     DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
}

static struct doveadm_mail_cmd_context *cmd_mailbox_metadata_list_alloc(void)
{
	struct metadata_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct metadata_cmd_context);
	ctx->ctx.v.init = cmd_mailbox_metadata_list_init;
	ctx->ctx.v.run = cmd_mailbox_metadata_list_run;
	doveadm_print_init(DOVEADM_PRINT_TYPE_FLOW);
	return &ctx->ctx;
}

struct doveadm_mail_cmd cmd_mailbox_metadata_set = {
	cmd_mailbox_metadata_set_alloc, "mailbox metadata set",
	"<mailbox> <key> <value>"
};

struct doveadm_mail_cmd cmd_mailbox_metadata_unset = {
	cmd_mailbox_metadata_unset_alloc, "mailbox metadata unset",
	"<mailbox> <key>"
};

struct doveadm_mail_cmd cmd_mailbox_metadata_get = {
	cmd_mailbox_metadata_get_alloc, "mailbox metadata get",
	"<mailbox> <key>"
};

struct doveadm_mail_cmd cmd_mailbox_metadata_list = {
	cmd_mailbox_metadata_list_alloc, "mailbox metadata list",
	"<mailbox> [<key prefix>]"
};
