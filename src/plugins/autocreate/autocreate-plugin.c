/* Copyright (c) 2007-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "autocreate-plugin.h"

#include <stdlib.h>

const char *autocreate_plugin_version = PACKAGE_VERSION;

static void (*autocreate_next_hook_mail_namespaces_created)
	(struct mail_namespace *ns);

static void
autocreate_mailbox(struct mail_namespace *namespaces, const char *name)
{
	struct mail_namespace *ns;
	const char *str;
	enum mail_error error;

	ns = mail_namespace_find(namespaces, &name);
	if (ns == NULL) {
		if (getenv("DEBUG") != NULL)
			i_info("autocreate: No namespace found for %s", name);
		return;
	}

	if (mail_storage_mailbox_create(ns->storage, name, FALSE) < 0) {
		str = mail_storage_get_last_error(ns->storage, &error);
		if (error != MAIL_ERROR_EXISTS && getenv("DEBUG") != NULL) {
			i_info("autocreate: Failed to create mailbox %s: %s",
			       name, str);
		}
	}
}

static void autocreate_mailboxes(struct mail_namespace *namespaces)
{
	char env_name[20];
	const char *name;
	unsigned int i;

	i = 1;
	name = getenv("AUTOCREATE");
	while (name != NULL) {
		autocreate_mailbox(namespaces, name);

		i_snprintf(env_name, sizeof(env_name), "AUTOCREATE%d", ++i);
		name = getenv(env_name);
	}
}

static void
autosubscribe_mailbox(struct mail_namespace *namespaces, const char *name)
{
	struct mail_namespace *ns;
	const char *str;
	enum mail_error error;

	ns = mail_namespace_find_subscribable(namespaces, &name);
	if (ns == NULL) {
		if (getenv("DEBUG") != NULL)
			i_info("autocreate: No namespace found for %s", name);
		return;
	}

	if (mailbox_list_set_subscribed(ns->list, name, TRUE) < 0) {
		str = mailbox_list_get_last_error(ns->list, &error);
		if (error != MAIL_ERROR_EXISTS && getenv("DEBUG") != NULL) {
			i_info("autocreate: Failed to subscribe mailbox %s: %s",
			       name, str);
		}
	}
}

static void autosubscribe_mailboxes(struct mail_namespace *namespaces)
{
	char env_name[20];
	const char *name;
	unsigned int i;

	i = 1;
	name = getenv("AUTOSUBSCRIBE");
	while (name != NULL) {
		autosubscribe_mailbox(namespaces, name);

		i_snprintf(env_name, sizeof(env_name), "AUTOSUBSCRIBE%d", ++i);
		name = getenv(env_name);
	}
}

static void
autocreate_mail_namespaces_created(struct mail_namespace *namespaces)
{
	autocreate_mailboxes(namespaces);
	autosubscribe_mailboxes(namespaces);

	if (autocreate_next_hook_mail_namespaces_created != NULL)
		autocreate_next_hook_mail_namespaces_created(namespaces);
}

void autocreate_plugin_init(void)
{
	autocreate_next_hook_mail_namespaces_created =
		hook_mail_namespaces_created;
	hook_mail_namespaces_created = autocreate_mail_namespaces_created;
}

void autocreate_plugin_deinit(void)
{
	hook_mail_namespaces_created =
		autocreate_next_hook_mail_namespaces_created;
}
