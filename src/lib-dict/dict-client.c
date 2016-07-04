/* Copyright (c) 2005-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "llist.h"
#include "str.h"
#include "strescape.h"
#include "time-util.h"
#include "connection.h"
#include "ostream.h"
#include "eacces-error.h"
#include "dict-private.h"
#include "dict-client.h"

#include <unistd.h>
#include <fcntl.h>

/* Disconnect from dict server after this many milliseconds of idling after
   sending a command. Because dict server does blocking dict accesses, it can
   handle only one client at a time. This is why the default timeout is zero,
   so that there won't be many dict processes just doing nothing. Zero means
   that the socket is disconnected immediately after returning to ioloop. */
#define DICT_CLIENT_DEFAULT_TIMEOUT_MSECS 0

/* Abort dict lookup after this many seconds. */
#define DICT_CLIENT_REQUEST_TIMEOUT_MSECS 30000
/* Log a warning if dict lookup takes longer than this many milliseconds. */
#define DICT_CLIENT_REQUEST_WARN_TIMEOUT_MSECS 5000

struct client_dict_cmd {
	int refcount;
	struct client_dict *dict;
	struct timeval start_time;
	char *query;

	bool retry_errors;
	bool no_replies;
	bool unfinished;
	bool background;

	void (*callback)(struct client_dict_cmd *cmd,
			 const char *line, const char *error);
        struct client_dict_iterate_context *iter;

	struct {
		dict_lookup_callback_t *lookup;
		dict_transaction_commit_callback_t *commit;
		void *context;
	} api_callback;
};

struct dict_connection {
	struct connection conn;
	struct client_dict *dict;
};

struct client_dict {
	struct dict dict;
	struct dict_connection conn;

	char *uri, *username;
	enum dict_data_type value_type;

	time_t last_failed_connect;
	char *last_connect_error;

	struct ioloop *ioloop, *prev_ioloop;
	struct timeout *to_requests;
	struct timeout *to_idle;
	unsigned int idle_msecs;
	struct timeval last_input;

	ARRAY(struct client_dict_cmd *) cmds;
	struct client_dict_transaction_context *transactions;

	unsigned int transaction_id_counter;
};

struct client_dict_iter_result {
	const char *key, *value;
};

struct client_dict_iterate_context {
	struct dict_iterate_context ctx;
	char *error;

	pool_t results_pool;
	ARRAY(struct client_dict_iter_result) results;
	unsigned int result_idx;

	bool async;
	bool finished;
	bool deinit;
};

struct client_dict_transaction_context {
	struct dict_transaction_context ctx;
	struct client_dict_transaction_context *prev, *next;

	char *error;

	unsigned int id;

	bool sent_begin:1;
};

static struct connection_list *dict_connections;

static int client_dict_connect(struct client_dict *dict, const char **error_r);
static void client_dict_disconnect(struct client_dict *dict, const char *reason);

static struct client_dict_cmd *
client_dict_cmd_init(struct client_dict *dict, const char *query)
{
	struct client_dict_cmd *cmd;

	io_loop_time_refresh();

	cmd = i_new(struct client_dict_cmd, 1);
	cmd->refcount = 1;
	cmd->dict = dict;
	cmd->query = i_strdup(query);
	cmd->start_time = ioloop_timeval;
	return cmd;
}

static void client_dict_cmd_ref(struct client_dict_cmd *cmd)
{
	i_assert(cmd->refcount > 0);
	cmd->refcount++;
}

static bool client_dict_cmd_unref(struct client_dict_cmd *cmd)
{
	i_assert(cmd->refcount > 0);
	if (--cmd->refcount > 0)
		return TRUE;

	i_free(cmd->query);
	i_free(cmd);
	return FALSE;
}

static void dict_pre_api_callback(struct client_dict *dict)
{
	if (dict->prev_ioloop != NULL) {
		/* Don't let callback see that we've created our
		   internal ioloop in case it wants to add some ios
		   or timeouts. */
		current_ioloop = dict->prev_ioloop;
	}
}

static void dict_post_api_callback(struct client_dict *dict)
{
	if (dict->prev_ioloop != NULL) {
		current_ioloop = dict->ioloop;
		/* stop client_dict_wait() */
		io_loop_stop(dict->ioloop);
	}
}

static bool
dict_cmd_callback_line(struct client_dict_cmd *cmd, const char *line)
{
	cmd->unfinished = FALSE;
	cmd->callback(cmd, line, NULL);
	return !cmd->unfinished;
}

static void
dict_cmd_callback_error(struct client_dict_cmd *cmd, const char *error)
{
	cmd->unfinished = FALSE;
	if (cmd->callback != NULL)
		cmd->callback(cmd, NULL, error);
	i_assert(!cmd->unfinished);
}

static void client_dict_input_timeout(struct client_dict *dict)
{
	int diff = timeval_diff_msecs(&ioloop_timeval, &dict->last_input);

	client_dict_disconnect(dict, t_strdup_printf(
		"Timeout: No input from dict for %u.%03u secs",
		diff/1000, diff%1000));
}

static int
client_dict_cmd_query_send(struct client_dict *dict, const char *query)
{
	struct const_iovec iov[2];
	ssize_t ret;

	iov[0].iov_base = query;
	iov[0].iov_len = strlen(query);
	iov[1].iov_base = "\n";
	iov[1].iov_len = 1;
	ret = o_stream_sendv(dict->conn.conn.output, iov, 2);
	if (ret < 0)
		return -1;
	i_assert((size_t)ret == iov[0].iov_len + 1);
	return 0;
}

static bool
client_dict_cmd_send(struct client_dict *dict, struct client_dict_cmd **_cmd,
		     const char **error_r)
{
	struct client_dict_cmd *cmd = *_cmd;
	const char *error = NULL;
	bool retry = cmd->retry_errors;
	int ret;

	*_cmd = NULL;

	/* we're no longer idling. even with no_replies=TRUE we're going to
	   wait for COMMIT/ROLLBACK. */
	if (dict->to_idle != NULL)
		timeout_remove(&dict->to_idle);

	if (client_dict_connect(dict, &error) < 0) {
		retry = FALSE;
		ret = -1;
	} else {
		ret = client_dict_cmd_query_send(dict, cmd->query);
		if (ret < 0) {
			error = t_strdup_printf("write(%s) failed: %s", dict->conn.conn.name,
					o_stream_get_error(dict->conn.conn.output));
		}
	}
	if (ret < 0 && retry) {
		/* Reconnect and try again. */
		client_dict_disconnect(dict, error);
		if (client_dict_connect(dict, &error) < 0)
			;
		else if (client_dict_cmd_query_send(dict, cmd->query) < 0) {
			error = t_strdup_printf("write(%s) failed: %s", dict->conn.conn.name,
				o_stream_get_error(dict->conn.conn.output));
		} else {
			ret = 0;
		}
	}

	if (cmd->no_replies) {
		/* just send and forget */
		client_dict_cmd_unref(cmd);
		return TRUE;
	} else if (ret < 0) {
		i_assert(error != NULL);
		dict_cmd_callback_error(cmd, error);
		client_dict_cmd_unref(cmd);
		if (error_r != NULL)
			*error_r = error;
		return FALSE;
	} else {
		if (dict->to_requests == NULL) {
			dict->to_requests =
				timeout_add(DICT_CLIENT_REQUEST_TIMEOUT_MSECS,
					    client_dict_input_timeout, dict);
		}
		array_append(&dict->cmds, &cmd, 1);
		return TRUE;
	}
}

static bool
client_dict_transaction_send_begin(struct client_dict_transaction_context *ctx)
{
	struct client_dict *dict = (struct client_dict *)ctx->ctx.dict;
	struct client_dict_cmd *cmd;
	const char *query, *error;

	i_assert(ctx->error == NULL);

	ctx->sent_begin = TRUE;

	/* transactions commands don't have replies. only COMMIT has. */
	query = t_strdup_printf("%c%u", DICT_PROTOCOL_CMD_BEGIN, ctx->id);
	cmd = client_dict_cmd_init(dict, query);
	cmd->no_replies = TRUE;
	cmd->retry_errors = TRUE;
	if (!client_dict_cmd_send(dict, &cmd, &error)) {
		ctx->error = i_strdup(error);
		return FALSE;
	}
	return TRUE;
}

static void
client_dict_send_transaction_query(struct client_dict_transaction_context *ctx,
				   const char *query)
{
	struct client_dict *dict = (struct client_dict *)ctx->ctx.dict;
	struct client_dict_cmd *cmd;
	const char *error;

	if (ctx->error != NULL)
		return;

	if (!ctx->sent_begin) {
		if (!client_dict_transaction_send_begin(ctx))
			return;
	}

	cmd = client_dict_cmd_init(dict, query);
	cmd->no_replies = TRUE;
	if (!client_dict_cmd_send(dict, &cmd, &error))
		ctx->error = i_strdup(error);
}

static bool client_dict_is_finished(struct client_dict *dict)
{
	return dict->transactions == NULL && array_count(&dict->cmds) == 0;
}

static void client_dict_timeout(struct client_dict *dict)
{
	if (client_dict_is_finished(dict))
		client_dict_disconnect(dict, "Idle disconnection");
}

static void client_dict_add_timeout(struct client_dict *dict)
{
	if (dict->to_idle != NULL) {
		if (dict->idle_msecs > 0)
			timeout_reset(dict->to_idle);
	} else if (client_dict_is_finished(dict)) {
		dict->to_idle = timeout_add(dict->idle_msecs,
					    client_dict_timeout, dict);
		if (dict->to_requests != NULL)
			timeout_remove(&dict->to_requests);
	}
}

static int dict_conn_input_line(struct connection *_conn, const char *line)
{
	struct dict_connection *conn = (struct dict_connection *)_conn;
	struct client_dict *dict = conn->dict;
	struct client_dict_cmd *const *cmds;
	unsigned int count;
	bool finished;
	int diff;

	dict->last_input = ioloop_timeval;
	if (dict->to_requests != NULL)
		timeout_reset(dict->to_requests);

	cmds = array_get(&conn->dict->cmds, &count);
	if (count == 0) {
		i_error("%s: Received reply without pending commands: %s",
			dict->conn.conn.name, line);
		return -1;
	}
	i_assert(!cmds[0]->no_replies);

	client_dict_cmd_ref(cmds[0]);
	finished = dict_cmd_callback_line(cmds[0], line);
	if (!client_dict_cmd_unref(cmds[0])) {
		/* disconnected during command handling */
		return -1;
	}
	if (!finished) {
		/* more lines needed for this command */
		return 1;
	}
	diff = cmds[0]->background ? 0 :
		timeval_diff_msecs(&ioloop_timeval, &cmds[0]->start_time);
	if (diff >= DICT_CLIENT_REQUEST_WARN_TIMEOUT_MSECS) {
		i_warning("read(%s): dict lookup took %u.%03u seconds: %s",
			  dict->conn.conn.name, diff/1000, diff % 1000,
			  cmds[0]->query);
	}
	client_dict_cmd_unref(cmds[0]);
	array_delete(&dict->cmds, 0, 1);

	client_dict_add_timeout(dict);
	return 1;
}

static int client_dict_connect(struct client_dict *dict, const char **error_r)
{
	const char *query, *error;

	if (dict->conn.conn.fd_in != -1)
		return 0;
	if (dict->last_failed_connect == ioloop_time) {
		/* Try again later */
		*error_r = dict->last_connect_error;
		return -1;
	}

	if (connection_client_connect(&dict->conn.conn) < 0) {
		dict->last_failed_connect = ioloop_time;
		if (errno == EACCES) {
			error = eacces_error_get("net_connect_unix",
						 dict->conn.conn.name);
		} else {
			error = t_strdup_printf(
				"net_connect_unix(%s) failed: %m", dict->conn.conn.name);
		}
		i_free(dict->last_connect_error);
		dict->last_connect_error = i_strdup(error);
		*error_r = error;
		return -1;
	}

	query = t_strdup_printf("%c%u\t%u\t%d\t%s\t%s\n",
				DICT_PROTOCOL_CMD_HELLO,
				DICT_CLIENT_PROTOCOL_MAJOR_VERSION,
				DICT_CLIENT_PROTOCOL_MINOR_VERSION,
				dict->value_type, dict->username, dict->uri);
	o_stream_nsend_str(dict->conn.conn.output, query);
	client_dict_add_timeout(dict);
	return 0;
}

static void
client_dict_abort_commands(struct client_dict *dict, const char *reason)
{
	ARRAY(struct client_dict_cmd *) cmds_copy;
	struct client_dict_cmd *const *cmdp;

	/* abort all commands */
	t_array_init(&cmds_copy, array_count(&dict->cmds));
	array_append_array(&cmds_copy, &dict->cmds);
	array_clear(&dict->cmds);

	array_foreach(&cmds_copy, cmdp) {
		dict_cmd_callback_error(*cmdp, reason);
		client_dict_cmd_unref(*cmdp);
	}
}

static void client_dict_disconnect(struct client_dict *dict, const char *reason)
{
	struct client_dict_transaction_context *ctx, *next;

	client_dict_abort_commands(dict, reason);

	/* all transactions that have sent BEGIN are no longer valid */
	for (ctx = dict->transactions; ctx != NULL; ctx = next) {
		next = ctx->next;
		if (ctx->sent_begin && ctx->error == NULL)
			ctx->error = i_strdup(reason);
	}

	if (dict->to_idle != NULL)
		timeout_remove(&dict->to_idle);
	if (dict->to_requests != NULL)
		timeout_remove(&dict->to_requests);
	connection_disconnect(&dict->conn.conn);
}

static void dict_conn_destroy(struct connection *_conn)
{
	struct dict_connection *conn = (struct dict_connection *)_conn;

	client_dict_disconnect(conn->dict, connection_disconnect_reason(_conn));
}

static const struct connection_settings dict_conn_set = {
	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1,
	.client = TRUE
};

static const struct connection_vfuncs dict_conn_vfuncs = {
	.destroy = dict_conn_destroy,
	.input_line = dict_conn_input_line
};

static int
client_dict_init(struct dict *driver, const char *uri,
		 const struct dict_settings *set,
		 struct dict **dict_r, const char **error_r)
{
	struct ioloop *old_ioloop = current_ioloop;
	struct client_dict *dict;
	const char *p, *dest_uri, *path;
	unsigned int idle_msecs = DICT_CLIENT_DEFAULT_TIMEOUT_MSECS;

	/* uri = [idle_msecs=<n>:] [<path>] ":" <uri> */
	if (strncmp(uri, "idle_msecs=", 11) == 0) {
		p = strchr(uri+11, ':');
		if (p == NULL) {
			*error_r = t_strdup_printf("Invalid URI: %s", uri);
			return -1;
		}
		if (str_to_uint(t_strdup_until(uri+11, p), &idle_msecs) < 0) {
			*error_r = "Invalid idle_msecs";
			return -1;
		}
		uri = p+1;
	}
	dest_uri = strchr(uri, ':');
	if (dest_uri == NULL) {
		*error_r = t_strdup_printf("Invalid URI: %s", uri);
		return -1;
	}

	if (dict_connections == NULL) {
		dict_connections = connection_list_init(&dict_conn_set,
							&dict_conn_vfuncs);
	}

	dict = i_new(struct client_dict, 1);
	dict->dict = *driver;
	dict->conn.dict = dict;
	dict->value_type = set->value_type;
	dict->username = i_strdup(set->username);
	dict->idle_msecs = idle_msecs;
	i_array_init(&dict->cmds, 32);

	if (uri[0] == ':') {
		/* default path */
		path = t_strconcat(set->base_dir,
			"/"DEFAULT_DICT_SERVER_SOCKET_FNAME, NULL);
	} else if (uri[0] == '/') {
		/* absolute path */
		path = t_strdup_until(uri, dest_uri);
	} else {
		/* relative path to base_dir */
		path = t_strconcat(set->base_dir, "/",
			t_strdup_until(uri, dest_uri), NULL);
	}
	connection_init_client_unix(dict_connections, &dict->conn.conn, path);
	dict->uri = i_strdup(dest_uri + 1);

	dict->ioloop = io_loop_create();
	io_loop_set_current(old_ioloop);
	*dict_r = &dict->dict;
	return 0;
}

static void client_dict_deinit(struct dict *_dict)
{
	struct client_dict *dict = (struct client_dict *)_dict;
	struct ioloop *old_ioloop = current_ioloop;

	client_dict_disconnect(dict, "Deinit");
	connection_deinit(&dict->conn.conn);

	i_assert(dict->transactions == NULL);
	i_assert(array_count(&dict->cmds) == 0);

	io_loop_set_current(dict->ioloop);
	io_loop_destroy(&dict->ioloop);
	io_loop_set_current(old_ioloop);

	array_free(&dict->cmds);
	i_free(dict->last_connect_error);
	i_free(dict->username);
	i_free(dict->uri);
	i_free(dict);

	if (dict_connections->connections == NULL)
		connection_list_deinit(&dict_connections);
}

static int client_dict_wait(struct dict *_dict)
{
	struct client_dict *dict = (struct client_dict *)_dict;

	if (array_count(&dict->cmds) == 0)
		return 0;

	dict->prev_ioloop = current_ioloop;
	io_loop_set_current(dict->ioloop);
	dict_switch_ioloop(_dict);
	while (array_count(&dict->cmds) > 0)
		io_loop_run(dict->ioloop);

	io_loop_set_current(dict->prev_ioloop);
	dict->prev_ioloop = NULL;

	dict_switch_ioloop(_dict);
	return 0;
}

static bool client_dict_switch_ioloop(struct dict *_dict)
{
	struct client_dict *dict = (struct client_dict *)_dict;

	if (dict->to_idle != NULL)
		dict->to_idle = io_loop_move_timeout(&dict->to_idle);
	if (dict->to_requests != NULL)
		dict->to_requests = io_loop_move_timeout(&dict->to_requests);
	connection_switch_ioloop(&dict->conn.conn);
	return array_count(&dict->cmds) > 0;
}

static void
client_dict_lookup_async_callback(struct client_dict_cmd *cmd, const char *line,
				  const char *error)
{
	struct client_dict *dict = cmd->dict;
	struct dict_lookup_result result;

	memset(&result, 0, sizeof(result));
	if (error != NULL) {
		result.ret = -1;
		result.error = error;
	} else switch (*line) {
	case DICT_PROTOCOL_REPLY_OK:
		result.value = t_str_tabunescape(line + 1);
		result.ret = 1;
		break;
	case DICT_PROTOCOL_REPLY_NOTFOUND:
		result.ret = 0;
		break;
	case DICT_PROTOCOL_REPLY_FAIL:
		result.error = line[1] == '\0' ? "dict-server returned failure" :
			t_strdup_printf("dict-server returned failure: %s",
			t_str_tabunescape(line+1));
		result.ret = -1;
		break;
	default:
		result.error = t_strdup_printf(
			"dict-client: Invalid lookup '%s' reply: %s",
			cmd->query, line);
		client_dict_disconnect(dict, result.error);
		result.ret = -1;
		break;
	}
	dict_pre_api_callback(dict);
	cmd->api_callback.lookup(&result, cmd->api_callback.context);
	dict_post_api_callback(dict);
}

static void
client_dict_lookup_async(struct dict *_dict, const char *key,
			 dict_lookup_callback_t *callback, void *context)
{
	struct client_dict *dict = (struct client_dict *)_dict;
	struct client_dict_cmd *cmd;
	const char *query;

	query = t_strdup_printf("%c%s", DICT_PROTOCOL_CMD_LOOKUP,
				str_tabescape(key));
	cmd = client_dict_cmd_init(dict, query);
	cmd->callback = client_dict_lookup_async_callback;
	cmd->api_callback.lookup = callback;
	cmd->api_callback.context = context;
	cmd->retry_errors = TRUE;

	client_dict_cmd_send(dict, &cmd, NULL);
}

static void client_dict_lookup_callback(const struct dict_lookup_result *result,
					void *context)
{
	struct dict_lookup_result *result_copy = context;

	*result_copy = *result;
}

static int client_dict_lookup(struct dict *_dict, pool_t pool, const char *key,
			      const char **value_r)
{
	struct dict_lookup_result result;

	memset(&result, 0, sizeof(result));
	result.ret = -2;

	client_dict_lookup_async(_dict, key, client_dict_lookup_callback, &result);
	if (result.ret == -2)
		client_dict_wait(_dict);

	switch (result.ret) {
	case -1:
		i_error("dict-client: Lookup '%s' failed: %s", key, result.error);
		return -1;
	case 0:
		*value_r = NULL;
		return 0;
	case 1:
		*value_r = p_strdup(pool, result.value);
		return 1;
	}
	i_unreached();
}

static void client_dict_iterate_free(struct client_dict_iterate_context *ctx)
{
	if (!ctx->deinit || !ctx->finished)
		return;
	i_free(ctx->error);
	i_free(ctx);
}

static void
client_dict_iter_api_callback(struct client_dict_iterate_context *ctx,
			      struct client_dict *dict)
{
	if (ctx->deinit) {
		/* iterator was already deinitialized */
		return;
	}
	if (ctx->ctx.async_callback != NULL) {
		dict_pre_api_callback(dict);
		ctx->ctx.async_callback(ctx->ctx.async_context);
		dict_post_api_callback(dict);
	} else {
		/* synchronous lookup */
		io_loop_stop(dict->ioloop);
	}
}

static void
client_dict_iter_async_callback(struct client_dict_cmd *cmd, const char *line,
				const char *error)
{
	struct client_dict_iterate_context *ctx = cmd->iter;
	struct client_dict *dict = cmd->dict;
	struct client_dict_iter_result *result;
	const char *key = NULL, *value = NULL;

	if (ctx->deinit)
		cmd->background = TRUE;

	if (error != NULL) {
		/* failed */
	} else switch (*line) {
	case '\0':
		/* end of iteration */
		ctx->finished = TRUE;
		client_dict_iter_api_callback(ctx, dict);
		client_dict_iterate_free(ctx);
		return;
	case DICT_PROTOCOL_REPLY_OK:
		/* key \t value */
		key = line+1;
		value = strchr(key, '\t');
		break;
	case DICT_PROTOCOL_REPLY_FAIL:
		error = t_strdup_printf("dict-server returned failure: %s", line+1);
		break;
	default:
		break;
	}
	if (value == NULL && error == NULL) {
		/* broken protocol */
		error = t_strdup_printf("dict client (%s) sent broken iterate reply: %s",
					dict->conn.conn.name, line);
		client_dict_disconnect(dict, error);
	}

	if (error != NULL) {
		if (ctx->error == NULL)
			ctx->error = i_strdup(error);
		ctx->finished = TRUE;
		if (dict->prev_ioloop != NULL) {
			/* stop client_dict_wait() */
			io_loop_stop(dict->ioloop);
		}
		client_dict_iterate_free(ctx);
		return;
	}
	cmd->unfinished = TRUE;

	if (ctx->deinit) {
		/* iterator was already deinitialized */
		return;
	}

	key = t_strdup_until(key, value++);
	result = array_append_space(&ctx->results);
	result->key = p_strdup(ctx->results_pool, t_str_tabunescape(key));
	result->value = p_strdup(ctx->results_pool, t_str_tabunescape(value));

	client_dict_iter_api_callback(ctx, dict);
}

static struct dict_iterate_context *
client_dict_iterate_init(struct dict *_dict, const char *const *paths,
			 enum dict_iterate_flags flags)
{
	struct client_dict *dict = (struct client_dict *)_dict;
        struct client_dict_iterate_context *ctx;
	struct client_dict_cmd *cmd;
	string_t *query = t_str_new(256);
	unsigned int i;

	ctx = i_new(struct client_dict_iterate_context, 1);
	ctx->ctx.dict = _dict;
	ctx->results_pool = pool_alloconly_create("client dict iteration", 512);
	ctx->async = (flags & DICT_ITERATE_FLAG_ASYNC) != 0;
	i_array_init(&ctx->results, 64);

	str_printfa(query, "%c%d", DICT_PROTOCOL_CMD_ITERATE, flags);
	for (i = 0; paths[i] != NULL; i++) {
		str_append_c(query, '\t');
			str_append(query, str_tabescape(paths[i]));
	}

	cmd = client_dict_cmd_init(dict, str_c(query));
	cmd->iter = ctx;
	cmd->callback = client_dict_iter_async_callback;
	cmd->retry_errors = TRUE;

	client_dict_cmd_send(dict, &cmd, NULL);
	return &ctx->ctx;
}

static bool client_dict_iterate(struct dict_iterate_context *_ctx,
				const char **key_r, const char **value_r)
{
	struct client_dict_iterate_context *ctx =
		(struct client_dict_iterate_context *)_ctx;
	const struct client_dict_iter_result *results;
	unsigned int count;

	if (ctx->error != NULL) {
		ctx->ctx.has_more = FALSE;
		return FALSE;
	}

	results = array_get(&ctx->results, &count);
	if (ctx->result_idx < count) {
		*key_r = results[ctx->result_idx].key;
		*value_r = results[ctx->result_idx].value;
		ctx->ctx.has_more = TRUE;
		ctx->result_idx++;
		return TRUE;
	}
	ctx->ctx.has_more = !ctx->finished;
	ctx->result_idx = 0;
	array_clear(&ctx->results);
	p_clear(ctx->results_pool);

	if (!ctx->async && ctx->ctx.has_more) {
		client_dict_wait(_ctx->dict);
		return client_dict_iterate(_ctx, key_r, value_r);
	}
	return FALSE;
}

static int client_dict_iterate_deinit(struct dict_iterate_context *_ctx)
{
	struct client_dict *dict = (struct client_dict *)_ctx->dict;
	struct client_dict_iterate_context *ctx =
		(struct client_dict_iterate_context *)_ctx;
	int ret = ctx->error != NULL ? -1 : 0;

	ctx->deinit = TRUE;

	if (ret < 0)
		i_error("dict-client: Iteration failed: %s", ctx->error);
	array_free(&ctx->results);
	pool_unref(&ctx->results_pool);
	client_dict_iterate_free(ctx);

	client_dict_add_timeout(dict);
	return ret;
}

static struct dict_transaction_context *
client_dict_transaction_init(struct dict *_dict)
{
	struct client_dict *dict = (struct client_dict *)_dict;
	struct client_dict_transaction_context *ctx;

	ctx = i_new(struct client_dict_transaction_context, 1);
	ctx->ctx.dict = _dict;
	ctx->id = ++dict->transaction_id_counter;

	DLLIST_PREPEND(&dict->transactions, ctx);
	return &ctx->ctx;
}

static void
client_dict_transaction_commit_callback(struct client_dict_cmd *cmd,
					const char *line, const char *error)
{
	struct client_dict *dict = cmd->dict;
	int ret = -1;

	if (error != NULL) {
		/* failed */
		i_error("dict-client: Commit failed: %s", error);
	} else switch (*line) {
	case DICT_PROTOCOL_REPLY_OK:
		ret = 1;
		break;
	case DICT_PROTOCOL_REPLY_NOTFOUND:
		ret = 0;
		break;
	case DICT_PROTOCOL_REPLY_FAIL: {
		const char *error = strchr(line+1, '\t');

		i_error("dict-client: server returned failure: %s",
			error != NULL ? t_str_tabunescape(error) : "");
		break;
	}
	default:
		ret = -1;
		error = t_strdup_printf("dict-client: Invalid commit reply: %s", line);
		i_error("%s", error);
		client_dict_disconnect(dict, error);
		break;
	}
	dict_pre_api_callback(dict);
	cmd->api_callback.commit(ret, cmd->api_callback.context);
	dict_post_api_callback(dict);
}

static void commit_sync_callback(int ret, void *context)
{
	int *ret_p = context;
	*ret_p = ret;
}

static int
client_dict_transaction_commit(struct dict_transaction_context *_ctx,
			       bool async,
			       dict_transaction_commit_callback_t *callback,
			       void *context)
{
	struct client_dict_transaction_context *ctx =
		(struct client_dict_transaction_context *)_ctx;
	struct client_dict *dict = (struct client_dict *)_ctx->dict;
	struct client_dict_cmd *cmd;
	const char *query;
	int ret = -1;

	DLLIST_REMOVE(&dict->transactions, ctx);

	if (ctx->sent_begin && ctx->error == NULL) {
		query = t_strdup_printf("%c%u", DICT_PROTOCOL_CMD_COMMIT, ctx->id);
		cmd = client_dict_cmd_init(dict, query);
		cmd->callback = client_dict_transaction_commit_callback;
		if (callback != NULL) {
			cmd->api_callback.commit = callback;
			cmd->api_callback.context = context;
		} else {
			cmd->api_callback.commit = commit_sync_callback;
			cmd->api_callback.context = &ret;
			if (async)
				cmd->background = TRUE;
		}
		if (client_dict_cmd_send(dict, &cmd, NULL)) {
			if (!async)
				client_dict_wait(_ctx->dict);
		}
	} else if (ctx->error != NULL) {
		/* already failed */
		if (callback != NULL)
			callback(-1, context);
		ret = -1;
	} else {
		/* nothing changed */
		if (callback != NULL)
			callback(1, context);
		ret = 1;
	}

	i_free(ctx->error);
	i_free(ctx);

	client_dict_add_timeout(dict);
	return ret;
}

static void
client_dict_transaction_rollback(struct dict_transaction_context *_ctx)
{
	struct client_dict_transaction_context *ctx =
		(struct client_dict_transaction_context *)_ctx;
	struct client_dict *dict = (struct client_dict *)_ctx->dict;

	if (ctx->sent_begin) {
		const char *query;

		query = t_strdup_printf("%c%u", DICT_PROTOCOL_CMD_ROLLBACK,
					ctx->id);
		client_dict_send_transaction_query(ctx, query);
	}

	DLLIST_REMOVE(&dict->transactions, ctx);
	i_free(ctx);

	client_dict_add_timeout(dict);
}

static void client_dict_set(struct dict_transaction_context *_ctx,
			    const char *key, const char *value)
{
	struct client_dict_transaction_context *ctx =
		(struct client_dict_transaction_context *)_ctx;
	const char *query;

	query = t_strdup_printf("%c%u\t%s\t%s",
				DICT_PROTOCOL_CMD_SET, ctx->id,
				str_tabescape(key),
				str_tabescape(value));
	client_dict_send_transaction_query(ctx, query);
}

static void client_dict_unset(struct dict_transaction_context *_ctx,
			      const char *key)
{
	struct client_dict_transaction_context *ctx =
		(struct client_dict_transaction_context *)_ctx;
	const char *query;

	query = t_strdup_printf("%c%u\t%s",
				DICT_PROTOCOL_CMD_UNSET, ctx->id,
				str_tabescape(key));
	client_dict_send_transaction_query(ctx, query);
}

static void client_dict_atomic_inc(struct dict_transaction_context *_ctx,
				   const char *key, long long diff)
{
	struct client_dict_transaction_context *ctx =
		(struct client_dict_transaction_context *)_ctx;
	const char *query;

	query = t_strdup_printf("%c%u\t%s\t%lld",
				DICT_PROTOCOL_CMD_ATOMIC_INC,
				ctx->id, str_tabescape(key), diff);
	client_dict_send_transaction_query(ctx, query);
}

struct dict dict_driver_client = {
	.name = "proxy",

	{
		.init = client_dict_init,
		.deinit = client_dict_deinit,
		.wait = client_dict_wait,
		.lookup = client_dict_lookup,
		.iterate_init = client_dict_iterate_init,
		.iterate = client_dict_iterate,
		.iterate_deinit = client_dict_iterate_deinit,
		.transaction_init = client_dict_transaction_init,
		.transaction_commit = client_dict_transaction_commit,
		.transaction_rollback = client_dict_transaction_rollback,
		.set = client_dict_set,
		.unset = client_dict_unset,
		.atomic_inc = client_dict_atomic_inc,
		.lookup_async = client_dict_lookup_async,
		.switch_ioloop = client_dict_switch_ioloop
	}
};
