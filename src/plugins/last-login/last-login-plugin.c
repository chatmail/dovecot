/* Copyright (c) 2014-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "dict.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "mail-storage-private.h"
#include "mail-storage-hooks.h"
#include "last-login-plugin.h"

#define LAST_LOGIN_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, last_login_user_module)

#define LAST_LOGIN_DEFAULT_KEY_PREFIX "last-login/"

struct last_login_user {
	union mail_user_module_context module_ctx;
	struct dict *dict;
	struct timeout *to;
};

const char *last_login_plugin_version = DOVECOT_ABI_VERSION;

static MODULE_CONTEXT_DEFINE_INIT(last_login_user_module,
				  &mail_user_module_register);

static void last_login_dict_deinit(struct mail_user *user)
{
	struct last_login_user *luser = LAST_LOGIN_USER_CONTEXT(user);

	if (luser->dict != NULL) {
		(void)dict_wait(luser->dict);
		dict_deinit(&luser->dict);
	}
	/* remove timeout after dict_wait(), which may trigger
	   last_login_dict_commit() */
	if (luser->to != NULL)
		timeout_remove(&luser->to);
}

static void last_login_user_deinit(struct mail_user *user)
{
	struct last_login_user *luser = LAST_LOGIN_USER_CONTEXT(user);

	last_login_dict_deinit(user);
	luser->module_ctx.super.deinit(user);
}

static void last_login_dict_commit(int ret ATTR_UNUSED, void *context)
{
	struct mail_user *user = context;
	struct last_login_user *luser = LAST_LOGIN_USER_CONTEXT(user);

	/* don't deinit the dict immediately here, lib-dict will just crash */
	luser->to = timeout_add(0, last_login_dict_deinit, user);
}

static void last_login_mail_user_created(struct mail_user *user)
{
	struct mail_user_vfuncs *v = user->vlast;
	struct last_login_user *luser;
	struct dict *dict;
	struct dict_settings set;
	struct dict_transaction_context *trans;
	const char *dict_value, *key_name, *error;

	if (user->autocreated) {
		/* we want to handle only logged in users,
		   not lda's raw user or accessed shared users */
		return;
	}

	dict_value = mail_user_plugin_getenv(user, "last_login_dict");
	if (dict_value == NULL)
		return;

	memset(&set, 0, sizeof(set));
	set.username = user->username;
	set.base_dir = user->set->base_dir;
	if (mail_user_get_home(user, &set.home_dir) <= 0)
		set.home_dir = NULL;
	if (dict_init_full(dict_value, &set, &dict, &error) < 0) {
		i_error("last_login_dict: dict_init(%s) failed: %s",
			dict_value, error);
		return;
	}

	luser = p_new(user->pool, struct last_login_user, 1);
	luser->module_ctx.super = *v;
	user->vlast = &luser->module_ctx.super;
	v->deinit = last_login_user_deinit;

	luser->dict = dict;
	MODULE_CONTEXT_SET(user, last_login_user_module, luser);

	key_name = mail_user_plugin_getenv(user, "last_login_key");
	if (key_name == NULL) {
		key_name = t_strdup_printf(LAST_LOGIN_DEFAULT_KEY_PREFIX"%s",
					   user->username);
	}
	key_name = t_strconcat(DICT_PATH_SHARED, key_name, NULL);

	trans = dict_transaction_begin(dict);
	dict_set(trans, key_name, dec2str(ioloop_time));
	dict_transaction_commit_async(&trans, last_login_dict_commit, user);
}

static struct mail_storage_hooks last_login_mail_storage_hooks = {
	.mail_user_created = last_login_mail_user_created
};

void last_login_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &last_login_mail_storage_hooks);
}

void last_login_plugin_deinit(void)
{
	mail_storage_hooks_remove(&last_login_mail_storage_hooks);
}
