/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "module-dir.h"
#include "quota-plugin.h"
#include "quota-private.h"
#include "doveadm-print.h"
#include "doveadm-mail.h"

const char *doveadm_quota_plugin_version = DOVECOT_ABI_VERSION;

void doveadm_quota_plugin_init(struct module *module);
void doveadm_quota_plugin_deinit(void);

static int cmd_quota_get_root(struct quota_root *root)
{
	const char *const *res;
	const char *error;
	uint64_t value, limit;
	enum quota_get_result qret;
	int ret = 0;

	res = quota_root_get_resources(root);
	for (; *res != NULL; res++) {
		qret = quota_get_resource(root, "", *res, &value, &limit, &error);
		doveadm_print(root->set->name);
		doveadm_print(*res);
		if (qret == QUOTA_GET_RESULT_LIMITED) {
			doveadm_print_num(value);
			doveadm_print_num(limit);
			if (limit > 0)
				doveadm_print_num(value*100 / limit);
			else
				doveadm_print("0");
		} else if (qret == QUOTA_GET_RESULT_UNLIMITED) {
			doveadm_print_num(value);
			doveadm_print("-");
			doveadm_print("0");
		} else {
			i_error("Failed to get quota resource %s: %s",
				*res, error);
			doveadm_print("error");
			doveadm_print("error");
			doveadm_print("error");
			ret = -1;
		}
	}
	return ret;
}

static int
cmd_quota_get_run(struct doveadm_mail_cmd_context *ctx,
		  struct mail_user *user)
{
	struct quota_user *quser = QUOTA_USER_CONTEXT(user);
	struct quota_root *const *root;

	if (quser == NULL) {
		i_error("Quota not enabled");
		doveadm_mail_failed_error(ctx, MAIL_ERROR_NOTFOUND);
		return -1;
	}

	int ret = 0;
	array_foreach(&quser->quota->roots, root)
		if (cmd_quota_get_root(*root) < 0)
			ret = -1;
	if (ret < 0)
		doveadm_mail_failed_error(ctx, MAIL_ERROR_TEMP);
	return ret;
}

static void cmd_quota_get_init(struct doveadm_mail_cmd_context *ctx ATTR_UNUSED,
			       const char *const args[] ATTR_UNUSED)
{
	doveadm_print_header("root", "Quota name", 0);
	doveadm_print_header("type", "Type", 0);
	doveadm_print_header("value", "Value",
			     DOVEADM_PRINT_HEADER_FLAG_RIGHT_JUSTIFY);
	doveadm_print_header("limit", "Limit",
			     DOVEADM_PRINT_HEADER_FLAG_RIGHT_JUSTIFY);
	doveadm_print_header("percent", "%",
			     DOVEADM_PRINT_HEADER_FLAG_RIGHT_JUSTIFY);
}

static struct doveadm_mail_cmd_context *
cmd_quota_get_alloc(void)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_mail_cmd_context);
	ctx->v.run = cmd_quota_get_run;
	ctx->v.init = cmd_quota_get_init;
	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	return ctx;
}

static int
cmd_quota_recalc_run(struct doveadm_mail_cmd_context *ctx ATTR_UNUSED,
		     struct mail_user *user)
{
	struct quota_user *quser = QUOTA_USER_CONTEXT(user);
	struct quota_root *const *root;
	struct quota_transaction_context trans;

	if (quser == NULL) {
		i_error("Quota not enabled");
		doveadm_mail_failed_error(ctx, MAIL_ERROR_NOTFOUND);
		return -1;
	}

	i_zero(&trans);
	trans.quota = quser->quota;
	trans.recalculate = QUOTA_RECALCULATE_FORCED;

	array_foreach(&quser->quota->roots, root) {
		const char *error;
		if ((*root)->backend.v.update(*root, &trans, &error) < 0)
			i_error("Recalculating quota failed: %s", error);
		if ((*root)->backend.v.flush != NULL)
			(*root)->backend.v.flush(*root);
	}
	return 0;
}

static struct doveadm_mail_cmd_context *
cmd_quota_recalc_alloc(void)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_mail_cmd_context);
	ctx->v.run = cmd_quota_recalc_run;
	return ctx;
}

static struct doveadm_cmd_ver2 quota_commands[] = {
	{
		.name = "quota get",
		.usage = "",
		.mail_cmd = cmd_quota_get_alloc,
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAMS_END
	},
	{
		.name = "quota recalc",
		.usage = "",
		.mail_cmd = cmd_quota_recalc_alloc,
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAMS_END
	}
};

void doveadm_quota_plugin_init(struct module *module ATTR_UNUSED)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(quota_commands); i++)
		doveadm_cmd_register_ver2(&quota_commands[i]);
}

void doveadm_quota_plugin_deinit(void)
{
}
