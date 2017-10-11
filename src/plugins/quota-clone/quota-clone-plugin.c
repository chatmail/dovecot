/* Copyright (c) 2015-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "module-context.h"
#include "ioloop.h"
#include "dict.h"
#include "mail-storage-private.h"
#include "quota.h"
#include "quota-clone-plugin.h"

/* If mailbox is kept open for this many milliseconds after quota update,
   flush quota-clone. */
#define QUOTA_CLONE_FLUSH_DELAY_MSECS (10*1000)

#define DICT_QUOTA_CLONE_PATH DICT_PATH_PRIVATE"quota/"
#define DICT_QUOTA_CLONE_BYTES_PATH DICT_QUOTA_CLONE_PATH"storage"
#define DICT_QUOTA_CLONE_COUNT_PATH DICT_QUOTA_CLONE_PATH"messages"

#define QUOTA_CLONE_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, quota_clone_user_module)
#define QUOTA_CLONE_CONTEXT(obj) \
	MODULE_CONTEXT(obj, quota_clone_storage_module)

static MODULE_CONTEXT_DEFINE_INIT(quota_clone_user_module,
				  &mail_user_module_register);
static MODULE_CONTEXT_DEFINE_INIT(quota_clone_storage_module,
				  &mail_storage_module_register);

struct quota_clone_user {
	union mail_user_module_context module_ctx;
	struct dict *dict;
	bool quota_flushing;
};

struct quota_clone_mailbox {
	union mailbox_module_context module_ctx;
	struct timeout *to_quota_flush;
	bool quota_changed;
};

static void quota_clone_flush_real(struct mailbox *box)
{
	struct quota_clone_mailbox *qbox = QUOTA_CLONE_CONTEXT(box);
	struct quota_clone_user *quser =
		QUOTA_CLONE_USER_CONTEXT(box->storage->user);
	struct dict_transaction_context *trans;
	struct quota_root_iter *iter;
	struct quota_root *root;
	uint64_t bytes_value, count_value, limit;
	int ret_bytes, ret_count;

	/* we'll clone the first quota root */
	iter = quota_root_iter_init(box);
	root = quota_root_iter_next(iter);
	quota_root_iter_deinit(&iter);
	if (root == NULL) {
		/* no quota roots defined for this mailbox - ignore */
		qbox->quota_changed = FALSE;
		return;
	}

	/* get new values first */
	ret_bytes = quota_get_resource(root, "", QUOTA_NAME_STORAGE_BYTES,
				       &bytes_value, &limit);
	if (ret_bytes < 0) {
		i_error("quota_clone_plugin: Failed to lookup current quota bytes");
		return;
	}
	ret_count = quota_get_resource(root, "", QUOTA_NAME_MESSAGES,
				       &count_value, &limit);
	if (ret_count < 0) {
		i_error("quota_clone_plugin: Failed to lookup current quota count");
		return;
	}

	/* update resources always regardless of existence,
	   FIXME: This should be fixed in v2.3 */
	trans = dict_transaction_begin(quser->dict);
	dict_set(trans, DICT_QUOTA_CLONE_BYTES_PATH,
		 t_strdup_printf("%llu", (unsigned long long)bytes_value));
	dict_set(trans, DICT_QUOTA_CLONE_COUNT_PATH,
		 t_strdup_printf("%llu", (unsigned long long)count_value));
	if (dict_transaction_commit(&trans) < 0)
		i_error("quota_clone_plugin: Failed to commit dict update");
	else
		qbox->quota_changed = FALSE;
}

static void quota_clone_flush(struct mailbox *box)
{
	struct quota_clone_mailbox *qbox = QUOTA_CLONE_CONTEXT(box);
	struct quota_clone_user *quser =
		QUOTA_CLONE_USER_CONTEXT(box->storage->user);

	if (qbox->to_quota_flush != NULL)
		timeout_remove(&qbox->to_quota_flush);

	if (quser->quota_flushing) {
		/* recursing back from quota recalculation */
	} else if (qbox->quota_changed) {
		quser->quota_flushing = TRUE;
		quota_clone_flush_real(box);
		quser->quota_flushing = FALSE;
	}
}

static void quota_clone_changed(struct mailbox *box)
{
	struct quota_clone_mailbox *qbox = QUOTA_CLONE_CONTEXT(box);

	qbox->quota_changed = TRUE;
	if (qbox->to_quota_flush == NULL) {
		qbox->to_quota_flush = timeout_add(QUOTA_CLONE_FLUSH_DELAY_MSECS,
						   quota_clone_flush, box);
	}
}

static int quota_clone_save_finish(struct mail_save_context *ctx)
{
	struct quota_clone_mailbox *qbox =
		QUOTA_CLONE_CONTEXT(ctx->transaction->box);

	quota_clone_changed(ctx->transaction->box);
	return qbox->module_ctx.super.save_finish(ctx);
}

static int
quota_clone_copy(struct mail_save_context *ctx, struct mail *mail)
{
	struct quota_clone_mailbox *qbox =
		QUOTA_CLONE_CONTEXT(ctx->transaction->box);

	quota_clone_changed(ctx->transaction->box);
	return qbox->module_ctx.super.copy(ctx, mail);
}

static void
quota_clone_mailbox_sync_notify(struct mailbox *box, uint32_t uid,
				enum mailbox_sync_type sync_type)
{
	struct quota_clone_mailbox *qbox = QUOTA_CLONE_CONTEXT(box);

	if (qbox->module_ctx.super.sync_notify != NULL)
		qbox->module_ctx.super.sync_notify(box, uid, sync_type);

	if (sync_type == MAILBOX_SYNC_TYPE_EXPUNGE)
		quota_clone_changed(box);
}

static void quota_clone_mailbox_close(struct mailbox *box)
{
	struct quota_clone_mailbox *qbox = QUOTA_CLONE_CONTEXT(box);

	qbox->module_ctx.super.close(box);

	quota_clone_flush(box);
}

static void quota_clone_mailbox_allocated(struct mailbox *box)
{
	struct quota_clone_user *quser =
		QUOTA_CLONE_USER_CONTEXT(box->storage->user);
	struct mailbox_vfuncs *v = box->vlast;
	struct quota_clone_mailbox *qbox;

	if (quser == NULL)
		return;

	qbox = p_new(box->pool, struct quota_clone_mailbox, 1);
	qbox->module_ctx.super = *v;
	box->vlast = &qbox->module_ctx.super;

	v->save_finish = quota_clone_save_finish;
	v->copy = quota_clone_copy;
	v->sync_notify = quota_clone_mailbox_sync_notify;
	v->close = quota_clone_mailbox_close;
	MODULE_CONTEXT_SET(box, quota_clone_storage_module, qbox);
}

static void quota_clone_mail_user_deinit(struct mail_user *user)
{
	struct quota_clone_user *quser = QUOTA_CLONE_USER_CONTEXT(user);

	dict_deinit(&quser->dict);
	quser->module_ctx.super.deinit(user);
}

static void quota_clone_mail_user_created(struct mail_user *user)
{
	struct quota_clone_user *quser;
	struct mail_user_vfuncs *v = user->vlast;
	struct dict_settings dict_set;
	struct dict *dict;
	const char *uri, *error;

	uri = mail_user_plugin_getenv(user, "quota_clone_dict");
	if (uri == NULL || uri[0] == '\0') {
		if (user->mail_debug) {
			i_debug("The quota_clone_dict setting is missing from configuration");
		}
		return;
	}

	i_zero(&dict_set);
	dict_set.username = user->username;
	dict_set.base_dir = user->set->base_dir;
	(void)mail_user_get_home(user, &dict_set.home_dir);
	if (dict_init_full(uri, &dict_set, &dict, &error) < 0) {
		i_error("quota_clone_dict: Failed to initialize '%s': %s",
			uri, error);
		return;
	}

	quser = p_new(user->pool, struct quota_clone_user, 1);
	quser->module_ctx.super = *v;
	user->vlast = &quser->module_ctx.super;
	v->deinit = quota_clone_mail_user_deinit;
	quser->dict = dict;
	MODULE_CONTEXT_SET(user, quota_clone_user_module, quser);
}

static struct mail_storage_hooks quota_clone_mail_storage_hooks = {
	.mailbox_allocated = quota_clone_mailbox_allocated,
	.mail_user_created = quota_clone_mail_user_created
};

void quota_clone_plugin_init(struct module *module ATTR_UNUSED)
{
	mail_storage_hooks_add(module, &quota_clone_mail_storage_hooks);
}

void quota_clone_plugin_deinit(void)
{
	mail_storage_hooks_remove(&quota_clone_mail_storage_hooks);
}

const char *quota_clone_plugin_dependencies[] = { "quota", NULL };
