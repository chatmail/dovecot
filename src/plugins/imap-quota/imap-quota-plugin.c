/* Copyright (c) 2005-2010 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "str.h"
#include "ostream.h"
#include "imap-quote.h"
#include "mail-namespace.h"
#include "commands.h"
#include "quota.h"
#include "quota-plugin.h"
#include "imap-quota-plugin.h"

#include <stdlib.h>

#define QUOTA_USER_SEPARATOR ':'

const char *imap_quota_plugin_version = PACKAGE_VERSION;

static const char *
imap_quota_root_get_name(struct mail_user *user, struct mail_user *owner,
			 struct quota_root *root)
{
	const char *name;

	name = quota_root_get_name(root);
	if (user == owner || owner == NULL)
		return name;
	return t_strdup_printf("%s%c%s", owner->username,
			       QUOTA_USER_SEPARATOR, name);
}

static void
quota_reply_write(string_t *str, struct mail_user *user,
		  struct mail_user *owner, struct quota_root *root)
{
        const char *name, *const *list;
	unsigned int i;
	uint64_t value, limit;
	int ret = 0;

	str_append(str, "* QUOTA ");
	name = imap_quota_root_get_name(user, owner, root);
	imap_quote_append_string(str, name, FALSE);

	str_append(str, " (");
	list = quota_root_get_resources(root);
	for (i = 0; *list != NULL; list++) {
		ret = quota_get_resource(root, "", *list, &value, &limit);
		if (ret < 0)
			break;
		if (ret > 0) {
			if (i > 0)
				str_append_c(str, ' ');
			str_printfa(str, "%s %llu %llu", *list,
				    (unsigned long long)value,
				    (unsigned long long)limit);
			i++;
		}
	}
	str_append(str, ")\r\n");

	if (ret < 0)
		str_append(str, "* BAD Internal quota calculation error\r\n");
}

static bool cmd_getquotaroot(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct mail_storage *storage;
	struct mail_namespace *ns;
	struct mailbox *box;
	struct quota_root_iter *iter;
        struct quota_root *root;
	const char *orig_mailbox, *mailbox, *name;
	string_t *quotaroot_reply, *quota_reply;

	/* <mailbox> */
	if (!client_read_string_args(cmd, 1, &mailbox))
		return FALSE;

	orig_mailbox = mailbox;
	storage = client_find_storage(cmd, &mailbox);
	if (storage == NULL)
		return TRUE;

	box = mailbox_open(&storage, mailbox, NULL, (MAILBOX_OPEN_READONLY |
						     MAILBOX_OPEN_FAST |
						     MAILBOX_OPEN_KEEP_RECENT));
	if (box == NULL) {
		client_send_storage_error(cmd, storage);
		return TRUE;
	}

	ns = mail_storage_get_namespace(storage);
	if (quota_set == NULL) {
		mailbox_close(&box);
		client_send_tagline(cmd, "OK No quota.");
		return TRUE;
	}
	if (ns->owner != NULL && ns->owner != client->user &&
	    !client->user->admin) {
		mailbox_close(&box);
		client_send_tagline(cmd, "NO Not showing other users' quota.");
		return TRUE;
	}

	/* build QUOTAROOT reply and QUOTA reply for all quota roots */
	quotaroot_reply = t_str_new(128);
	quota_reply = t_str_new(256);
	str_append(quotaroot_reply, "* QUOTAROOT ");
	imap_quote_append_string(quotaroot_reply, mailbox, FALSE);

	iter = quota_root_iter_init(box);
	while ((root = quota_root_iter_next(iter)) != NULL) {
		str_append_c(quotaroot_reply, ' ');
		name = imap_quota_root_get_name(client->user, ns->owner, root);
		imap_quote_append_string(quotaroot_reply, name, FALSE);

		quota_reply_write(quota_reply, client->user, ns->owner, root);
	}
	quota_root_iter_deinit(&iter);
	mailbox_close(&box);

	/* send replies */
	client_send_line(client, str_c(quotaroot_reply));
	o_stream_send(client->output, str_data(quota_reply),
		      str_len(quota_reply));
	client_send_tagline(cmd, "OK Getquotaroot completed.");
	return TRUE;
}

static bool cmd_getquota(struct client_command_context *cmd)
{
	struct mail_user *owner = cmd->client->user;
        struct quota_root *root;
	const char *root_name, *p;
	string_t *quota_reply;

	/* <quota root> */
	if (!client_read_string_args(cmd, 1, &root_name))
		return FALSE;

	if (quota_set == NULL) {
		client_send_tagline(cmd, "OK No quota.");
		return TRUE;
	}

	root = quota_root_lookup(cmd->client->user, root_name);
	if (root == NULL && cmd->client->user->admin) {
		/* we're an admin. see if there's a quota root for another
		   user. */
		p = strchr(root_name, QUOTA_USER_SEPARATOR);
		if (p != NULL) {
			owner = mail_user_find(cmd->client->user,
					       t_strdup_until(root_name, p));
			root = owner == NULL ? NULL :
				quota_root_lookup(owner, p + 1);
		}
	}
	if (root == NULL) {
		client_send_tagline(cmd, "NO Quota root doesn't exist.");
		return TRUE;
	}

	quota_reply = t_str_new(128);
	quota_reply_write(quota_reply, cmd->client->user, owner, root);
	o_stream_send(cmd->client->output, str_data(quota_reply),
		      str_len(quota_reply));

	client_send_tagline(cmd, "OK Getquota completed.");
	return TRUE;
}

static bool cmd_setquota(struct client_command_context *cmd)
{
	struct quota_root *root;
        const struct imap_arg *args, *arg;
	const char *root_name, *name, *error;
	uint64_t value;

	/* <quota root> <resource limits> */
	if (!client_read_args(cmd, 2, 0, &args))
		return FALSE;

	root_name = imap_arg_string(&args[0]);
	if (args[1].type != IMAP_ARG_LIST || root_name == NULL) {
		client_send_command_error(cmd, "Invalid arguments.");
		return TRUE;
	}

	if (quota_set == NULL) {
		client_send_tagline(cmd, "OK No quota.");
		return TRUE;
	}

	root = quota_root_lookup(cmd->client->user, root_name);
	if (root == NULL) {
		client_send_tagline(cmd, "NO Quota root doesn't exist.");
		return TRUE;
	}

        arg = IMAP_ARG_LIST_ARGS(&args[1]);
	for (; arg->type != IMAP_ARG_EOL; arg += 2) {
		name = imap_arg_string(arg);
		if (name == NULL || arg[1].type != IMAP_ARG_ATOM ||
		    !is_numeric(IMAP_ARG_STR(&arg[1]), '\0')) {
			client_send_command_error(cmd, "Invalid arguments.");
			return TRUE;
		}

                value = strtoull(IMAP_ARG_STR_NONULL(&arg[1]), NULL, 10);
		if (quota_set_resource(root, name, value, &error) < 0) {
			client_send_command_error(cmd, error);
			return TRUE;
		}
	}

	client_send_tagline(cmd, "OK Setquota completed.");
	return TRUE;
}

void imap_quota_plugin_init(void)
{
	command_register("GETQUOTAROOT", cmd_getquotaroot, 0);
	command_register("GETQUOTA", cmd_getquota, 0);
	command_register("SETQUOTA", cmd_setquota, 0);
	str_append(capability_string, " QUOTA");
}

void imap_quota_plugin_deinit(void)
{
	command_unregister("GETQUOTAROOT");
	command_unregister("GETQUOTA");
	command_unregister("SETQUOTA");
}