/* Copyright (C) 2005-2006 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "dict.h"
#include "quota-private.h"

#include <stdlib.h>

#define DICT_QUOTA_CURRENT_PATH DICT_PATH_PRIVATE"quota/"
#define DICT_QUOTA_CURRENT_BYTES_PATH DICT_QUOTA_CURRENT_PATH"storage"
#define DICT_QUOTA_CURRENT_COUNT_PATH DICT_QUOTA_CURRENT_PATH"messages"

struct dict_quota_root {
	struct quota_root root;
	struct dict *dict;

	uint64_t message_bytes_limit;
	uint64_t message_count_limit;

	unsigned int counting:1;
};

extern struct quota_backend quota_backend_dict;

static struct quota_root *
dict_quota_init(struct quota_setup *setup, const char *name)
{
	struct dict_quota_root *root;
	struct dict *dict;
	const char *uri, *const *args;
	unsigned long long message_bytes_limit = 0, message_count_limit = 0;

	uri = strchr(setup->data, ' ');
	if (uri == NULL) {
		i_fatal("dict quota: URI missing from parameters: %s",
			setup->data);
	}

	t_push();
	args = t_strsplit(t_strdup_until(setup->data, uri++), ":");
	for (; *args != '\0'; args++) {
		if (strncmp(*args, "storage=", 8) == 0) {
			message_bytes_limit =
				strtoull(*args + 8, NULL, 10) * 1024;
		} else if (strncmp(*args, "messages=", 9) == 0)
			message_count_limit = strtoull(*args + 9, NULL, 10);
	}
	t_pop();

	if (getenv("DEBUG") != NULL) {
		i_info("dict quota: uri = %s", uri);
		i_info("dict quota: byte limit = %llu", message_bytes_limit);
		i_info("dict quota: count limit = %llu", message_count_limit);
	}

	dict = dict_init(uri, getenv("USER"));
	if (dict == NULL)
		i_fatal("dict quota: dict_init() failed");

	root = i_new(struct dict_quota_root, 1);
	root->root.name = i_strdup(name);
	root->root.v = quota_backend_dict.v;
	root->dict = dict;

	root->message_bytes_limit =
		message_bytes_limit == 0 ? (uint64_t)-1 : message_bytes_limit;
	root->message_count_limit =
		message_count_limit == 0 ? (uint64_t)-1 : message_count_limit;
	return &root->root;
}

static void dict_quota_deinit(struct quota_root *_root)
{
	struct dict_quota_root *root = (struct dict_quota_root *)_root;

	i_free(root->root.name);
	i_free(root);
}

static bool
dict_quota_add_storage(struct quota_root *root __attr_unused__,
		       struct mail_storage *storage __attr_unused__)
{
	return TRUE;
}

static void
dict_quota_remove_storage(struct quota_root *root __attr_unused__,
			  struct mail_storage *storage __attr_unused__)
{
}

static const char *const *
dict_quota_root_get_resources(struct quota_root *root __attr_unused__)
{
	static const char *resources[] = { QUOTA_NAME_STORAGE, NULL };

	return resources;
}

static struct mail_storage *
dict_quota_root_get_storage(struct quota_root *root)
{
	/* FIXME: figure out how to support multiple storages */
	struct mail_storage *const *storages;
	unsigned int count;

	storages = array_get(&root->storages, &count);
	i_assert(count > 0);

	return storages[0];
}

static int dict_quota_lookup(struct dict_quota_root *root, const char *path,
			     uint64_t *value_r)
{
	struct dict_transaction_context *dt;
	const char *value;
	uint64_t bytes, count;
	int ret;

	i_assert(!root->counting);

	t_push();
	ret = dict_lookup(root->dict, unsafe_data_stack_pool, path, &value);
	if (ret > 0) {
		*value_r = strtoull(value, NULL, 10);
		t_pop();
		return 0;
	}
	t_pop();

	if (ret < 0)
		return -1;

	/* not found, recalculate the quota */
	root->counting = TRUE;
	ret = quota_count_storage(dict_quota_root_get_storage(&root->root),
				  &bytes, &count);
	root->counting = FALSE;

	if (ret < 0)
		return -1;

	t_push();
	dt = dict_transaction_begin(root->dict);
	if (root->message_bytes_limit != (uint64_t)-1)
		dict_set(dt, DICT_QUOTA_CURRENT_BYTES_PATH, dec2str(bytes));
	if (root->message_count_limit != (uint64_t)-1)
		dict_set(dt, DICT_QUOTA_CURRENT_COUNT_PATH, dec2str(count));
	t_pop();

	if (dict_transaction_commit(dt) < 0)
		i_error("dict_quota: Couldn't update quota");

	if (strcmp(path, DICT_QUOTA_CURRENT_BYTES_PATH) == 0)
		*value_r = bytes;
	else {
		i_assert(strcmp(path, DICT_QUOTA_CURRENT_COUNT_PATH) == 0);
		*value_r = count;
	}
	return 0;
}

static int
dict_quota_get_resource(struct quota_root *_root, const char *name,
			uint64_t *value_r, uint64_t *limit_r)
{
	struct dict_quota_root *root = (struct dict_quota_root *)_root;

	if (strcmp(name, QUOTA_NAME_STORAGE) == 0) {
		if (root->message_bytes_limit == (uint64_t)-1)
			return 0;

		*limit_r = root->message_bytes_limit / 1024;
		if (dict_quota_lookup(root, DICT_QUOTA_CURRENT_BYTES_PATH,
				      value_r) < 0)
			return -1;
		*value_r /= 1024;
	} else if (strcmp(name, QUOTA_NAME_MESSAGES) == 0) {
		if (root->message_count_limit == (uint64_t)-1)
			return 0;

		*limit_r = root->message_count_limit;
		if (dict_quota_lookup(root, DICT_QUOTA_CURRENT_COUNT_PATH,
				      value_r) < 0)
			return -1;
	} else {
		return 0;
	}

	return 1;
}

static int
dict_quota_set_resource(struct quota_root *root,
			const char *name __attr_unused__,
			uint64_t value __attr_unused__)
{
	quota_set_error(root->setup->quota, MAIL_STORAGE_ERR_NO_PERMISSION);
	return -1;
}

static struct quota_root_transaction_context *
dict_quota_transaction_begin(struct quota_root *_root,
			     struct quota_transaction_context *_ctx,
			     struct mailbox *box __attr_unused__)
{
	struct dict_quota_root *root = (struct dict_quota_root *)_root;
	struct quota_root_transaction_context *ctx;

	ctx = i_new(struct quota_root_transaction_context, 1);
	ctx->root = _root;
	ctx->ctx = _ctx;

	ctx->bytes_limit = root->message_bytes_limit;
	ctx->count_limit = root->message_count_limit;

	if (root->counting) {
		/* created by quota_count_storage(), we don't care about
		   the quota there */
		ctx->bytes_limit = (uint64_t)-1;
		ctx->count_limit = (uint64_t)-1;
		return ctx;
	}

	t_push();
	if (ctx->bytes_limit != (uint64_t)-1) {
		if (dict_quota_lookup(root, DICT_QUOTA_CURRENT_BYTES_PATH,
				      &ctx->bytes_current) < 0)
			ctx->bytes_current = 0;
	}
	if (ctx->count_limit != (uint64_t)-1) {
		if (dict_quota_lookup(root, DICT_QUOTA_CURRENT_COUNT_PATH,
				      &ctx->count_current) < 0)
			ctx->bytes_current = 0;
	}
	t_pop();
	return ctx;
}

static int
dict_quota_transaction_commit(struct quota_root_transaction_context *ctx)
{
	struct dict_quota_root *root = (struct dict_quota_root *)ctx->root;
	struct dict_transaction_context *dt;

	dt = dict_transaction_begin(root->dict);
	if (ctx->bytes_limit != (uint64_t)-1) {
		dict_atomic_inc(dt, DICT_QUOTA_CURRENT_BYTES_PATH,
				ctx->bytes_diff);
	}
	if (ctx->count_limit != (uint64_t)-1) {
		dict_atomic_inc(dt, DICT_QUOTA_CURRENT_COUNT_PATH,
				ctx->count_diff);
	}
	if (dict_transaction_commit(dt) < 0)
		i_error("dict_quota: Couldn't update quota");

	i_free(ctx);
	return 0;
}

static void
dict_quota_transaction_rollback(struct quota_root_transaction_context *ctx)
{
	i_free(ctx);
}

struct quota_backend quota_backend_dict = {
	"dict",

	{
		dict_quota_init,
		dict_quota_deinit,

		dict_quota_add_storage,
		dict_quota_remove_storage,

		dict_quota_root_get_resources,

		dict_quota_get_resource,
		dict_quota_set_resource,

		dict_quota_transaction_begin,
		dict_quota_transaction_commit,
		dict_quota_transaction_rollback,

		quota_default_try_alloc,
		quota_default_try_alloc_bytes,
		quota_default_test_alloc_bytes,
		quota_default_alloc,
		quota_default_free
	}
};
