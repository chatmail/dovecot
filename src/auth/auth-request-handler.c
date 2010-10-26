/* Copyright (c) 2005-2010 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ioloop.h"
#include "array.h"
#include "aqueue.h"
#include "base64.h"
#include "hash.h"
#include "str.h"
#include "str-sanitize.h"
#include "auth-request.h"
#include "auth-master-connection.h"
#include "auth-request-handler.h"

#include <stdlib.h>

#define DEFAULT_AUTH_FAILURE_DELAY 2
#define AUTH_FAILURE_DELAY_CHECK_MSECS 500

struct auth_request_handler {
	int refcount;
	pool_t pool;
	struct hash_table *requests;

        struct auth *auth;
        unsigned int connect_uid, client_pid;

	auth_request_callback_t *callback;
	void *context;

	auth_request_callback_t *master_callback;
};

static ARRAY_DEFINE(auth_failures_arr, struct auth_request *);
static struct aqueue *auth_failures;
static struct timeout *to_auth_failures;
static unsigned int auth_failure_delay;

static void auth_failure_timeout(void *context);

#undef auth_request_handler_create
struct auth_request_handler *
auth_request_handler_create(struct auth *auth,
			    auth_request_callback_t *callback, void *context,
			    auth_request_callback_t *master_callback)
{
	struct auth_request_handler *handler;
	pool_t pool;

	pool = pool_alloconly_create("auth request handler", 4096);

	handler = p_new(pool, struct auth_request_handler, 1);
	handler->refcount = 1;
	handler->pool = pool;
	handler->requests = hash_table_create(default_pool, pool, 0, NULL, NULL);
	handler->auth = auth;
	handler->callback = callback;
	handler->context = context;
	handler->master_callback = master_callback;
	return handler;
}

void auth_request_handler_unref(struct auth_request_handler **_handler)
{
        struct auth_request_handler *handler = *_handler;
	struct hash_iterate_context *iter;
	void *key, *value;

	*_handler = NULL;
	i_assert(handler->refcount > 0);
	if (--handler->refcount > 0)
		return;

	iter = hash_table_iterate_init(handler->requests);
	while (hash_table_iterate(iter, &key, &value)) {
		struct auth_request *auth_request = value;

		auth_request_unref(&auth_request);
	}
	hash_table_iterate_deinit(&iter);

	/* notify parent that we're done with all requests */
	handler->callback(NULL, handler->context);

	hash_table_destroy(&handler->requests);
	pool_unref(&handler->pool);
}

void auth_request_handler_set(struct auth_request_handler *handler,
			      unsigned int connect_uid,
			      unsigned int client_pid)
{
	handler->connect_uid = connect_uid;
	handler->client_pid = client_pid;
}

static void auth_request_handler_remove(struct auth_request_handler *handler,
					struct auth_request *request)
{
	hash_table_remove(handler->requests, POINTER_CAST(request->id));
	auth_request_unref(&request);
}

void auth_request_handler_check_timeouts(struct auth_request_handler *handler)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	iter = hash_table_iterate_init(handler->requests);
	while (hash_table_iterate(iter, &key, &value)) {
		struct auth_request *request = value;

		if (request->last_access + AUTH_REQUEST_TIMEOUT < ioloop_time)
			auth_request_handler_remove(handler, request);
	}
	hash_table_iterate_deinit(&iter);
}

static void get_client_extra_fields(struct auth_request *request,
				    struct auth_stream_reply *reply)
{
	const char **fields, *extra_fields;
	unsigned int src, dest;
	bool seen_pass = FALSE;

	if (auth_stream_is_empty(request->extra_fields))
		return;

	extra_fields = auth_stream_reply_export(request->extra_fields);

	if (!request->proxy) {
		/* we only wish to remove all fields prefixed with "userdb_" */
		if (strstr(extra_fields, "userdb_") == NULL) {
			auth_stream_reply_import(reply, extra_fields);
			return;
		}
	}

	fields = t_strsplit(extra_fields, "\t");
	for (src = dest = 0; fields[src] != NULL; src++) {
		if (strncmp(fields[src], "userdb_", 7) != 0) {
			if (!seen_pass && strncmp(fields[src], "pass=", 5) == 0)
				seen_pass = TRUE;
			auth_stream_reply_import(reply, fields[src]);
		}
	}

	if (request->proxy) {
		/* we're proxying */
		if (!seen_pass && request->mech_password != NULL) {
			/* send back the password that was sent by user
			   (not the password in passdb). */
			auth_stream_reply_add(reply, "pass",
					      request->mech_password);
		}
		if (request->master_user != NULL) {
			/* the master username needs to be forwarded */
			auth_stream_reply_add(reply, "master",
					      request->master_user);
		}
	}
}

static void
auth_request_handle_failure(struct auth_request *request,
			    struct auth_stream_reply *reply)
{
        struct auth_request_handler *handler = request->context;

	if (request->delayed_failure) {
		/* we came here from flush_failures() */
		handler->callback(reply, handler->context);
		return;
	}

	/* remove the request from requests-list */
	auth_request_ref(request);
	auth_request_handler_remove(handler, request);

	if (request->no_failure_delay) {
		/* passdb specifically requested not to delay the
		   reply. */
		handler->callback(reply, handler->context);
		auth_request_unref(&request);
		return;
	}

	/* failure. don't announce it immediately to avoid
	   a) timing attacks, b) flooding */
	request->delayed_failure = TRUE;
	handler->refcount++;

	request->last_access = ioloop_time;
	aqueue_append(auth_failures, &request);
	if (to_auth_failures == NULL) {
		to_auth_failures =
			timeout_add(AUTH_FAILURE_DELAY_CHECK_MSECS,
				    auth_failure_timeout, NULL);
	}
}

static void auth_callback(struct auth_request *request,
			  enum auth_client_result result,
			  const void *auth_reply, size_t reply_size)
{
        struct auth_request_handler *handler = request->context;
	struct auth_stream_reply *reply;
	string_t *str;

	reply = auth_stream_reply_init(pool_datastack_create());
	switch (result) {
	case AUTH_CLIENT_RESULT_CONTINUE:
		auth_stream_reply_add(reply, "CONT", NULL);
		auth_stream_reply_add(reply, NULL, dec2str(request->id));

		str = t_str_new(MAX_BASE64_ENCODED_SIZE(reply_size));
		base64_encode(auth_reply, reply_size, str);
		auth_stream_reply_add(reply, NULL, str_c(str));

		request->accept_input = TRUE;
		handler->callback(reply, handler->context);
		break;
	case AUTH_CLIENT_RESULT_SUCCESS:
		auth_request_proxy_finish(request, TRUE);

		auth_stream_reply_add(reply, "OK", NULL);
		auth_stream_reply_add(reply, NULL, dec2str(request->id));
		auth_stream_reply_add(reply, "user", request->user);
		if (reply_size > 0) {
			str = t_str_new(MAX_BASE64_ENCODED_SIZE(reply_size));
			base64_encode(auth_reply, reply_size, str);
			auth_stream_reply_add(reply, "resp", str_c(str));
		}
		get_client_extra_fields(request, reply);
		if (request->no_login || handler->master_callback == NULL) {
			/* this request doesn't have to wait for master
			   process to pick it up. delete it */
			auth_request_handler_remove(handler, request);
		}
		handler->callback(reply, handler->context);
		break;
	case AUTH_CLIENT_RESULT_FAILURE:
		auth_request_proxy_finish(request, FALSE);

		auth_stream_reply_add(reply, "FAIL", NULL);
		auth_stream_reply_add(reply, NULL, dec2str(request->id));
		if (request->user != NULL)
			auth_stream_reply_add(reply, "user", request->user);

		if (request->internal_failure)
			auth_stream_reply_add(reply, "temp", NULL);
		else if (request->master_user != NULL) {
			/* authentication succeeded, but we can't log in
			   as the wanted user */
			auth_stream_reply_add(reply, "authz", NULL);
		}
		if (request->no_failure_delay)
			auth_stream_reply_add(reply, "nodelay", NULL);
		get_client_extra_fields(request, reply);

		auth_request_handle_failure(request, reply);
		break;
	}
	/* NOTE: request may be destroyed now */

        auth_request_handler_unref(&handler);
}

static void auth_request_handler_auth_fail(struct auth_request_handler *handler,
					   struct auth_request *request,
					   const char *reason)
{
	struct auth_stream_reply *reply;

	auth_request_log_info(request, request->mech->mech_name, "%s", reason);

	reply = auth_stream_reply_init(pool_datastack_create());
	auth_stream_reply_add(reply, "FAIL", NULL);
	auth_stream_reply_add(reply, NULL, dec2str(request->id));
	auth_stream_reply_add(reply, "reason", reason);

	handler->callback(reply, handler->context);
	auth_request_handler_remove(handler, request);
}

bool auth_request_handler_auth_begin(struct auth_request_handler *handler,
				     const char *args)
{
	const struct mech_module *mech;
	struct auth_request *request;
	const char *const *list, *name, *arg, *initial_resp;
	const void *initial_resp_data;
	size_t initial_resp_len;
	unsigned int id;
	buffer_t *buf;

	/* <id> <mechanism> [...] */
	list = t_strsplit(args, "\t");
	if (list[0] == NULL || list[1] == NULL) {
		i_error("BUG: Authentication client %u "
			"sent broken AUTH request", handler->client_pid);
		return FALSE;
	}

	id = (unsigned int)strtoul(list[0], NULL, 10);

	mech = mech_module_find(list[1]);
	if (mech == NULL) {
		/* unsupported mechanism */
		i_error("BUG: Authentication client %u requested unsupported "
			"authentication mechanism %s", handler->client_pid,
			str_sanitize(list[1], MAX_MECH_NAME_LEN));
		return FALSE;
	}

	request = auth_request_new(handler->auth, mech, auth_callback, handler);
	request->connect_uid = handler->connect_uid;
	request->client_pid = handler->client_pid;
	request->id = id;

	/* parse optional parameters */
	initial_resp = NULL;
	for (list += 2; *list != NULL; list++) {
		arg = strchr(*list, '=');
		if (arg == NULL) {
			name = *list;
			arg = "";
		} else {
			name = t_strdup_until(*list, arg);
			arg++;
		}

		if (auth_request_import(request, name, arg))
			;
		else if (strcmp(name, "resp") == 0) {
			initial_resp = arg;
			/* this must be the last parameter */
			list++;
			break;
		}
	}

	if (*list != NULL) {
		i_error("BUG: Authentication client %u "
			"sent AUTH parameters after 'resp'",
			handler->client_pid);
		return FALSE;
	}

	if (request->service == NULL) {
		i_error("BUG: Authentication client %u "
			"didn't specify service in request",
			handler->client_pid);
		return FALSE;
	}

	hash_table_insert(handler->requests, POINTER_CAST(id), request);

	if (request->auth->ssl_require_client_cert &&
	    !request->valid_client_cert) {
		/* we fail without valid certificate */
                auth_request_handler_auth_fail(handler, request,
			"Client didn't present valid SSL certificate");
		return TRUE;
	}

	/* Empty initial response is a "=" base64 string. Completely empty
	   string shouldn't really be sent, but at least Exim does it,
	   so just allow it for backwards compatibility.. */
	if (initial_resp == NULL || *initial_resp == '\0') {
		initial_resp_data = NULL;
		initial_resp_len = 0;
	} else {
		size_t len = strlen(initial_resp);
		buf = buffer_create_dynamic(pool_datastack_create(),
					    MAX_BASE64_DECODED_SIZE(len));
		if (base64_decode(initial_resp, len, NULL, buf) < 0) {
                        auth_request_handler_auth_fail(handler, request,
				"Invalid base64 data in initial response");
			return TRUE;
		}
		initial_resp_data = buf->data;
		initial_resp_len = buf->used;
	}

	/* handler is referenced until auth_callback is called. */
	handler->refcount++;
	auth_request_initial(request, initial_resp_data, initial_resp_len);
	return TRUE;
}

bool auth_request_handler_auth_continue(struct auth_request_handler *handler,
					const char *args)
{
	struct auth_request *request;
	const char *data;
	size_t data_len;
	buffer_t *buf;
	unsigned int id;

	data = strchr(args, '\t');
	if (data == NULL) {
		i_error("BUG: Authentication client sent broken CONT request");
		return FALSE;
	}
	data++;

	id = (unsigned int)strtoul(args, NULL, 10);

	request = hash_table_lookup(handler->requests, POINTER_CAST(id));
	if (request == NULL) {
		struct auth_stream_reply *reply;

		reply = auth_stream_reply_init(pool_datastack_create());
		auth_stream_reply_add(reply, "FAIL", NULL);
		auth_stream_reply_add(reply, NULL, dec2str(id));
		auth_stream_reply_add(reply, "reason", "Timeouted");
		handler->callback(reply, handler->context);
		return TRUE;
	}

	/* accept input only once after mechanism has sent a CONT reply */
	if (!request->accept_input) {
		auth_request_handler_auth_fail(handler, request,
					       "Unexpected continuation");
		return TRUE;
	}
	request->accept_input = FALSE;

	data_len = strlen(data);
	buf = buffer_create_dynamic(pool_datastack_create(),
				    MAX_BASE64_DECODED_SIZE(data_len));
	if (base64_decode(data, data_len, NULL, buf) < 0) {
		auth_request_handler_auth_fail(handler, request,
			"Invalid base64 data in continued response");
		return TRUE;
	}

	/* handler is referenced until auth_callback is called. */
	handler->refcount++;
	auth_request_continue(request, buf->data, buf->used);
	return TRUE;
}

static void userdb_callback(enum userdb_result result,
			    struct auth_request *request)
{
        struct auth_request_handler *handler = request->context;
	struct auth_stream_reply *reply;

	i_assert(request->state == AUTH_REQUEST_STATE_USERDB);

	request->state = AUTH_REQUEST_STATE_FINISHED;

	if (request->userdb_lookup_failed)
		result = USERDB_RESULT_INTERNAL_FAILURE;

	reply = auth_stream_reply_init(pool_datastack_create());
	switch (result) {
	case USERDB_RESULT_INTERNAL_FAILURE:
		auth_stream_reply_add(reply, "FAIL", NULL);
		auth_stream_reply_add(reply, NULL, dec2str(request->id));
		break;
	case USERDB_RESULT_USER_UNKNOWN:
		auth_stream_reply_add(reply, "NOTFOUND", NULL);
		auth_stream_reply_add(reply, NULL, dec2str(request->id));
		break;
	case USERDB_RESULT_OK:
		auth_stream_reply_add(reply, "USER", NULL);
		auth_stream_reply_add(reply, NULL, dec2str(request->id));
		if (request->master_user != NULL) {
			auth_stream_reply_add(request->userdb_reply,
					      "master_user",
					      request->master_user);
		}
		auth_stream_reply_import(reply,
			auth_stream_reply_export(request->userdb_reply));
		break;
	}
	handler->master_callback(reply, request->master);

	auth_master_connection_unref(&request->master);
	auth_request_unref(&request);
        auth_request_handler_unref(&handler);
}

void auth_request_handler_master_request(struct auth_request_handler *handler,
					 struct auth_master_connection *master,
					 unsigned int id,
					 unsigned int client_id)
{
	struct auth_request *request;
	struct auth_stream_reply *reply;

	reply = auth_stream_reply_init(pool_datastack_create());

	request = hash_table_lookup(handler->requests, POINTER_CAST(client_id));
	if (request == NULL) {
		i_error("Master request %u.%u not found",
			handler->client_pid, client_id);
		auth_stream_reply_add(reply, "NOTFOUND", NULL);
		auth_stream_reply_add(reply, NULL, dec2str(id));
		handler->master_callback(reply, master);
		return;
	}

	auth_request_ref(request);
	auth_request_handler_remove(handler, request);

	if (request->state != AUTH_REQUEST_STATE_FINISHED ||
	    !request->successful) {
		i_error("Master requested unfinished authentication request "
			"%u.%u", handler->client_pid, client_id);
		auth_stream_reply_add(reply, "NOTFOUND", NULL);
		auth_stream_reply_add(reply, NULL, dec2str(id));
		handler->master_callback(reply, master);
		auth_request_unref(&request);
	} else {
		/* the request isn't being referenced anywhere anymore,
		   so we can do a bit of kludging.. replace the request's
		   old client_id with master's id. */
		request->state = AUTH_REQUEST_STATE_USERDB;
		request->id = id;
		request->context = handler;
		request->master = master;

		/* master and handler are referenced until userdb_callback i
		   s called. */
		auth_master_connection_ref(master);
		handler->refcount++;
		auth_request_lookup_user(request, userdb_callback);
	}
}

void auth_request_handler_flush_failures(bool flush_all)
{
	struct auth_request **auth_requests, *auth_request;
	unsigned int i, count;
	time_t diff;

	count = aqueue_count(auth_failures);
	if (count == 0) {
		if (to_auth_failures != NULL)
			timeout_remove(&to_auth_failures);
		return;
	}

	auth_requests = array_idx_modifiable(&auth_failures_arr, 0);
	for (i = 0; i < count; i++) {
		auth_request = auth_requests[aqueue_idx(auth_failures, 0)];

		diff = ioloop_time - auth_request->last_access;
		if (diff < (time_t)auth_failure_delay && !flush_all)
			break;

		aqueue_delete_tail(auth_failures);

		i_assert(auth_request->state == AUTH_REQUEST_STATE_FINISHED);
		auth_request->callback(auth_request,
				       AUTH_CLIENT_RESULT_FAILURE, NULL, 0);
		auth_request_unref(&auth_request);
	}
}

static void auth_failure_timeout(void *context ATTR_UNUSED)
{
	auth_request_handler_flush_failures(FALSE);
}

void auth_request_handler_init(void)
{
	const char *env;

	env = getenv("FAILURE_DELAY");
	auth_failure_delay = env != NULL ? atoi(env) :
		DEFAULT_AUTH_FAILURE_DELAY;

	i_array_init(&auth_failures_arr, 128);
	auth_failures = aqueue_init(&auth_failures_arr.arr);
}

void auth_request_handler_deinit(void)
{
	auth_request_handler_flush_failures(TRUE);
	array_free(&auth_failures_arr);
	aqueue_deinit(&auth_failures);

	if (to_auth_failures != NULL)
		timeout_remove(&to_auth_failures);
}