/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

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

#define QUOTA_CLONE_USER_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, quota_clone_user_module)
#define QUOTA_CLONE_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, quota_clone_user_module)
#define QUOTA_CLONE_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, quota_clone_storage_module)

static MODULE_CONTEXT_DEFINE_INIT(quota_clone_user_module,
				  &mail_user_module_register);
static MODULE_CONTEXT_DEFINE_INIT(quota_clone_storage_module,
				  &mail_storage_module_register);

struct quota_clone_user {
	union mail_user_module_context module_ctx;
	struct dict *dict;
	struct timeout *to_quota_flush;
	bool quota_changed;
	bool quota_flushing;
};

static void
quota_clone_dict_commit(const struct dict_commit_result *result,
			struct quota_clone_user *quser)
{
	switch (result->ret) {
	case DICT_COMMIT_RET_OK:
	case DICT_COMMIT_RET_NOTFOUND:
		if (!quser->quota_changed)
			timeout_remove(&quser->to_quota_flush);
		break;
	case DICT_COMMIT_RET_FAILED:
		quser->quota_changed = TRUE;
		i_error("quota_clone_dict: Failed to write value: %s",
			result->error);
		break;
	case DICT_COMMIT_RET_WRITE_UNCERTAIN:
		quser->quota_changed = TRUE;
		i_error("quota_clone_dict: Write was unconfirmed (timeout or disconnect): %s",
			result->error);
		break;
	}

	quser->quota_flushing = FALSE;
}

static bool quota_clone_flush_real(struct mail_user *user)
{
	struct quota_clone_user *quser =
		QUOTA_CLONE_USER_CONTEXT_REQUIRE(user);
	struct dict_transaction_context *trans;
	struct quota_root_iter *iter;
	struct quota_root *root;
	uint64_t bytes_value, count_value, limit;
	const char *error;
	enum quota_get_result bytes_res, count_res;

	/* we'll clone the first quota root */
	iter = quota_root_iter_init_user(user);
	root = quota_root_iter_next(iter);
	quota_root_iter_deinit(&iter);
	if (root == NULL) {
		/* no quota roots defined - ignore */
		quser->quota_changed = FALSE;
		return TRUE;
	}

	/* get new values first */
	bytes_res = quota_get_resource(root, "", QUOTA_NAME_STORAGE_BYTES,
				       &bytes_value, &limit, &error);
	if (bytes_res == QUOTA_GET_RESULT_INTERNAL_ERROR) {
		i_error("quota_clone_plugin: "
			"Failed to get quota resource "QUOTA_NAME_STORAGE_BYTES": %s",
			error);
		return TRUE;
	}
	count_res = quota_get_resource(root, "", QUOTA_NAME_MESSAGES,
				       &count_value, &limit, &error);
	if (count_res == QUOTA_GET_RESULT_INTERNAL_ERROR) {
		i_error("quota_clone_plugin: "
			"Failed to get quota resource "QUOTA_NAME_MESSAGES": %s",
			error);
		return TRUE;
	}
	if (bytes_res == QUOTA_GET_RESULT_UNKNOWN_RESOURCE &&
	    count_res == QUOTA_GET_RESULT_UNKNOWN_RESOURCE) {
		/* quota resources don't exist - no point in updating it */
		return TRUE;
	}
	if (bytes_res == QUOTA_GET_RESULT_BACKGROUND_CALC &&
	    count_res == QUOTA_GET_RESULT_BACKGROUND_CALC) {
		/* Blocked by an ongoing quota calculation - try again later */
		quser->quota_flushing = FALSE;
		return FALSE;
	}

	/* Then update the resources that exist. The resources' existence can't
	   change unless the quota backend is changed, so we don't worry about
	   the special case of lookup changing from
	   RESULT_LIMITED/RESULT_UNLIMITED to RESULT_UNKNOWN_RESOURCE, which
	   leaves the old value unchanged. */
	trans = dict_transaction_begin(quser->dict);
	if (bytes_res == QUOTA_GET_RESULT_LIMITED ||
	    bytes_res == QUOTA_GET_RESULT_UNLIMITED) {
		dict_set(trans, DICT_QUOTA_CLONE_BYTES_PATH,
			 t_strdup_printf("%"PRIu64, bytes_value));
	}
	if (count_res == QUOTA_GET_RESULT_LIMITED ||
	    count_res == QUOTA_GET_RESULT_UNLIMITED) {
		dict_set(trans, DICT_QUOTA_CLONE_COUNT_PATH,
			 t_strdup_printf("%"PRIu64, count_value));
	}
	quser->quota_changed = FALSE;
	dict_transaction_commit_async(&trans, quota_clone_dict_commit, quser);
	return FALSE;
}

static void quota_clone_flush(struct mail_user *user)
{
	struct quota_clone_user *quser =
		QUOTA_CLONE_USER_CONTEXT_REQUIRE(user);

	if (quser->quota_changed) {
		i_assert(quser->to_quota_flush != NULL);
		if (quser->quota_flushing) {
			/* async quota commit is running in background. timeout is still
			   active, so another update will be done later. */
		} else {
			quser->quota_flushing = TRUE;
			/* Returns TRUE if flushing action is complete. */
			if (quota_clone_flush_real(user)) {
				quser->quota_flushing = FALSE;
				timeout_remove(&quser->to_quota_flush);
			}
		}
	} else {
		timeout_remove(&quser->to_quota_flush);
	}
}

static struct mail_user *quota_mailbox_get_user(struct mailbox *box)
{
	struct mail_namespace *ns = mailbox_list_get_namespace(box->list);
	return ns->owner != NULL ? ns->owner : ns->user;
}

static void quota_clone_changed(struct mailbox *box)
{
	struct mail_user *user = quota_mailbox_get_user(box);
	struct quota_clone_user *quser =
		QUOTA_CLONE_USER_CONTEXT_REQUIRE(user);

	quser->quota_changed = TRUE;
	if (quser->to_quota_flush == NULL) {
		quser->to_quota_flush = timeout_add(QUOTA_CLONE_FLUSH_DELAY_MSECS,
						    quota_clone_flush, user);
	}
}

static int quota_clone_save_finish(struct mail_save_context *ctx)
{
	union mailbox_module_context *qbox =
		QUOTA_CLONE_CONTEXT(ctx->transaction->box);

	quota_clone_changed(ctx->transaction->box);
	return qbox->super.save_finish(ctx);
}

static int
quota_clone_copy(struct mail_save_context *ctx, struct mail *mail)
{
	union mailbox_module_context *qbox =
		QUOTA_CLONE_CONTEXT(ctx->transaction->box);

	quota_clone_changed(ctx->transaction->box);
	return qbox->super.copy(ctx, mail);
}

static void
quota_clone_mailbox_sync_notify(struct mailbox *box, uint32_t uid,
				enum mailbox_sync_type sync_type)
{
	union mailbox_module_context *qbox = QUOTA_CLONE_CONTEXT(box);

	if (qbox->super.sync_notify != NULL)
		qbox->super.sync_notify(box, uid, sync_type);

	if (sync_type == MAILBOX_SYNC_TYPE_EXPUNGE)
		quota_clone_changed(box);
}

static void quota_clone_mailbox_allocated(struct mailbox *box)
{
	struct quota_clone_user *quser =
		QUOTA_CLONE_USER_CONTEXT(box->storage->user);
	struct mailbox_vfuncs *v = box->vlast;
	union mailbox_module_context *qbox;

	if (quser == NULL)
		return;

	qbox = p_new(box->pool, union mailbox_module_context, 1);
	qbox->super = *v;
	box->vlast = &qbox->super;

	v->save_finish = quota_clone_save_finish;
	v->copy = quota_clone_copy;
	v->sync_notify = quota_clone_mailbox_sync_notify;
	MODULE_CONTEXT_SET_SELF(box, quota_clone_storage_module, qbox);
}

static void quota_clone_mail_user_deinit_pre(struct mail_user *user)
{
	struct quota_clone_user *quser = QUOTA_CLONE_USER_CONTEXT_REQUIRE(user);

	dict_wait(quser->dict);
	/* Check once more if quota needs to be updated. This needs to be done
	   in deinit_pre(), because at deinit() the quota is already
	   deinitialized. */
	if (quser->to_quota_flush != NULL) {
		i_assert(!quser->quota_flushing);
		quota_clone_flush(user);
		dict_wait(quser->dict);
		/* If dict update fails or background calculation is running,
		   the timeout is still set. Just forget about it. */
		timeout_remove(&quser->to_quota_flush);
	}
	quser->module_ctx.super.deinit_pre(user);
}

static void quota_clone_mail_user_deinit(struct mail_user *user)
{
	struct quota_clone_user *quser = QUOTA_CLONE_USER_CONTEXT_REQUIRE(user);

	/* wait once more, just in case something changed quota during
	   deinit_pre() */
	dict_wait(quser->dict);
	i_assert(quser->to_quota_flush == NULL);
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
		e_debug(user->event, "The quota_clone_dict setting is missing from configuration");
		return;
	}

	i_zero(&dict_set);
	dict_set.username = user->username;
	dict_set.base_dir = user->set->base_dir;
	dict_set.event_parent = user->event;
	(void)mail_user_get_home(user, &dict_set.home_dir);
	if (dict_init(uri, &dict_set, &dict, &error) < 0) {
		i_error("quota_clone_dict: Failed to initialize '%s': %s",
			uri, error);
		return;
	}

	quser = p_new(user->pool, struct quota_clone_user, 1);
	quser->module_ctx.super = *v;
	user->vlast = &quser->module_ctx.super;
	v->deinit_pre = quota_clone_mail_user_deinit_pre;
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
