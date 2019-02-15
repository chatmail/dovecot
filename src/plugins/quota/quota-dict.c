/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "dict.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "quota-private.h"


#define DICT_QUOTA_CURRENT_PATH DICT_PATH_PRIVATE"quota/"
#define DICT_QUOTA_CURRENT_BYTES_PATH DICT_QUOTA_CURRENT_PATH"storage"
#define DICT_QUOTA_CURRENT_COUNT_PATH DICT_QUOTA_CURRENT_PATH"messages"

struct dict_quota_root {
	struct quota_root root;
	struct dict *dict;
	struct timeout *to_update;
	bool disable_unset;
};

extern struct quota_backend quota_backend_dict;

static struct quota_root *dict_quota_alloc(void)
{
	struct dict_quota_root *root;

	root = i_new(struct dict_quota_root, 1);
	return &root->root;
}

static void handle_nounset_param(struct quota_root *_root, const char *param_value ATTR_UNUSED)
{
	((struct dict_quota_root *)_root)->disable_unset = TRUE;
}

static int dict_quota_init(struct quota_root *_root, const char *args,
			   const char **error_r)
{
	struct dict_quota_root *root = (struct dict_quota_root *)_root;
	struct dict_settings set;
	const char *username, *p, *error;

	const struct quota_param_parser dict_params[] = {
		{.param_name = "no-unset", .param_handler = handle_nounset_param},
		quota_param_hidden, quota_param_ignoreunlimited, quota_param_noenforcing, quota_param_ns,
		{.param_name = NULL}
	};

	p = args == NULL ? NULL : strchr(args, ':');
	if (p == NULL) {
		*error_r = "URI missing from parameters";
		return -1;
	}

	username = t_strdup_until(args, p);
	args = p+1;

	if (quota_parse_parameters(_root, &args, error_r, dict_params, FALSE) < 0)
		i_unreached();

	if (*username == '\0')
		username = _root->quota->user->username;

	if (_root->quota->set->debug) {
		i_debug("dict quota: user=%s, uri=%s, noenforcing=%d",
			username, args, _root->no_enforcing ? 1 : 0);
	}

	/* FIXME: we should use 64bit integer as datatype instead but before
	   it can actually be used don't bother */
	i_zero(&set);
	set.username = username;
	set.base_dir = _root->quota->user->set->base_dir;
	if (mail_user_get_home(_root->quota->user, &set.home_dir) <= 0)
		set.home_dir = NULL;
	if (dict_init(args, &set, &root->dict, &error) < 0) {
		*error_r = t_strdup_printf("dict_init(%s) failed: %s", args, error);
		return -1;
	}
	return 0;
}

static void dict_quota_deinit(struct quota_root *_root)
{
	struct dict_quota_root *root = (struct dict_quota_root *)_root;

	i_assert(root->to_update == NULL);

	if (root->dict != NULL) {
		dict_wait(root->dict);
		dict_deinit(&root->dict);
	}
	i_free(root);
}

static const char *const *
dict_quota_root_get_resources(struct quota_root *root ATTR_UNUSED)
{
	static const char *resources[] = {
		QUOTA_NAME_STORAGE_KILOBYTES, QUOTA_NAME_MESSAGES, NULL
	};

	return resources;
}

static enum quota_get_result
dict_quota_count(struct dict_quota_root *root,
		 bool want_bytes, uint64_t *value_r,
		 const char **error_r)
{
	struct dict_transaction_context *dt;
	uint64_t bytes, count;
	enum quota_get_result error_res;

	if (quota_count(&root->root, &bytes, &count, &error_res, error_r) < 0)
		return error_res;

	dt = dict_transaction_begin(root->dict);
	/* these unsets are mainly necessary for pgsql, because its
	   trigger otherwise increases quota without deleting it.
	   but some people with other databases want to store the
	   quota usage among other data in the same row, which
	   shouldn't be deleted. */
	if (!root->disable_unset) {
		dict_unset(dt, DICT_QUOTA_CURRENT_BYTES_PATH);
		dict_unset(dt, DICT_QUOTA_CURRENT_COUNT_PATH);
	}
	dict_set(dt, DICT_QUOTA_CURRENT_BYTES_PATH, dec2str(bytes));
	dict_set(dt, DICT_QUOTA_CURRENT_COUNT_PATH, dec2str(count));

	if (root->root.quota->set->debug) {
		i_debug("dict quota: Quota recalculated: "
			"count=%"PRIu64" bytes=%"PRIu64, count, bytes);
	}

	dict_transaction_commit_async(&dt, NULL, NULL);
	*value_r = want_bytes ? bytes : count;
	return QUOTA_GET_RESULT_LIMITED;
}

static enum quota_get_result
dict_quota_get_resource(struct quota_root *_root,
			const char *name, uint64_t *value_r,
			const char **error_r)
{
	struct dict_quota_root *root = (struct dict_quota_root *)_root;
	bool want_bytes;
	int ret;

	if (strcmp(name, QUOTA_NAME_STORAGE_BYTES) == 0)
		want_bytes = TRUE;
	else if (strcmp(name, QUOTA_NAME_MESSAGES) == 0)
		want_bytes = FALSE;
	else {
		*error_r = QUOTA_UNKNOWN_RESOURCE_ERROR_STRING;
		return QUOTA_GET_RESULT_UNKNOWN_RESOURCE;
	}

	const char *key, *value, *error;
	key = want_bytes ? DICT_QUOTA_CURRENT_BYTES_PATH :
		DICT_QUOTA_CURRENT_COUNT_PATH;
	ret = dict_lookup(root->dict, unsafe_data_stack_pool,
			  key, &value, &error);
	if (ret < 0) {
		*error_r = t_strdup_printf(
			"dict_lookup(%s) failed: %s", key, error);
		*value_r = 0;
		return QUOTA_GET_RESULT_INTERNAL_ERROR;
	}

	intmax_t tmp;
	/* recalculate quota if it's negative or if it wasn't found */
	if (ret == 0 || str_to_intmax(value, &tmp) < 0)
		tmp = -1;
	if (tmp >= 0)
		*value_r = tmp;
	else
		return dict_quota_count(root, want_bytes, value_r, error_r);
	return QUOTA_GET_RESULT_LIMITED;
}

static void dict_quota_recalc_timeout(struct dict_quota_root *root)
{
	uint64_t value;
	const char *error;

	timeout_remove(&root->to_update);
	if (dict_quota_count(root, TRUE, &value, &error)
	    <= QUOTA_GET_RESULT_INTERNAL_ERROR)
		i_error("quota-dict: Recalculation failed: %s", error);
}

static void dict_quota_update_callback(const struct dict_commit_result *result,
				       void *context)
{
	struct dict_quota_root *root = context;

	if (result->ret == 0) {
		/* row doesn't exist, need to recalculate it */
		if (root->to_update == NULL)
			root->to_update = timeout_add_short(0, dict_quota_recalc_timeout, root);
	} else if (result->ret < 0) {
		i_error("dict quota: Quota update failed: %s "
			"- Quota is now desynced", result->error);
	}
}

static int
dict_quota_update(struct quota_root *_root, 
		  struct quota_transaction_context *ctx,
		  const char **error_r)
{
	struct dict_quota_root *root = (struct dict_quota_root *) _root;
	struct dict_transaction_context *dt;
	uint64_t value;

	if (ctx->recalculate != QUOTA_RECALCULATE_DONT) {
		if (dict_quota_count(root, TRUE, &value, error_r)
		    <= QUOTA_GET_RESULT_INTERNAL_ERROR)
			return -1;
	} else {
		dt = dict_transaction_begin(root->dict);
		if (ctx->bytes_used != 0) {
			dict_atomic_inc(dt, DICT_QUOTA_CURRENT_BYTES_PATH,
					ctx->bytes_used);
		}
		if (ctx->count_used != 0) {
			dict_atomic_inc(dt, DICT_QUOTA_CURRENT_COUNT_PATH,
					ctx->count_used);
		}
		dict_transaction_no_slowness_warning(dt);
		dict_transaction_commit_async(&dt, dict_quota_update_callback,
					      root);
	}
	return 0;
}

static void dict_quota_flush(struct quota_root *_root)
{
	struct dict_quota_root *root = (struct dict_quota_root *)_root;

	dict_wait(root->dict);
	if (root->to_update != NULL) {
		dict_quota_recalc_timeout(root);
		dict_wait(root->dict);
	}
}

struct quota_backend quota_backend_dict = {
	.name = "dict",

	.v = {
		.alloc = dict_quota_alloc,
		.init = dict_quota_init,
		.deinit = dict_quota_deinit,
		.get_resources = dict_quota_root_get_resources,
		.get_resource = dict_quota_get_resource,
		.update = dict_quota_update,
		.flush = dict_quota_flush,
	}
};
