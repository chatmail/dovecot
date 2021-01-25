/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "strescape.h"
#include "llist.h"
#include "base64.h"
#include "hostpid.h"
#include "ioloop.h"
#include "istream.h"
#include "istream-chain.h"
#include "ostream.h"
#include "time-util.h"
#include "sleep.h"
#include "unlink-directory.h"
#include "write-full.h"
#include "connection.h"
#include "master-service.h"
#include "master-interface.h"
#include "test-common.h"
#include "test-subprocess.h"

#include "auth-client.h"

#define TEST_SOCKET "./auth-client-test"
#define CLIENT_PROGRESS_TIMEOUT     30
#define SERVER_KILL_TIMEOUT_SECS    20

static void main_deinit(void);

/*
 * Types
 */

struct server_connection {
	struct connection conn;

	void *context;

	pool_t pool;
};

typedef void test_server_init_t(void);
typedef bool test_client_init_t(void);

/*
 * State
 */

/* common */
static struct ioloop *ioloop;
static bool debug = FALSE;

/* server */
static struct io *io_listen;
static int fd_listen = -1;
static struct connection_list *server_conn_list;
static void (*test_server_input)(struct server_connection *conn);
static void (*test_server_init)(struct server_connection *conn);
static void (*test_server_deinit)(struct server_connection *conn);

/* client */

/*
 * Forward declarations
 */

/* server */
static void test_server_run(void);
static void server_connection_deinit(struct server_connection **_conn);

/* client */
static void test_client_deinit(void);

static int
test_client_auth_parallel(const char *mech, const char *username,
			  const char *password, unsigned int concurrency,
			  bool retry, const char **error_r);
static int
test_client_auth_simple(const char *mech, const char *username,
			const char *password, bool retry, const char **error_r);

/* test*/
static void
test_run_client_server(test_client_init_t *client_test,
		       test_server_init_t *server_test) ATTR_NULL(2);

/*
 * Connection refused
 */

/* server */

static void test_server_connection_refused(void)
{
	i_close_fd(&fd_listen);
	i_sleep_intr_secs(500);
}

/* client */

static bool test_client_connection_refused(void)
{
	const char *error;
	int ret;

	ret = test_client_auth_simple("PLAIN", "harrie", "frop", FALSE, &error);
	test_out_reason("run (ret == -1)", ret == -1, error);

	return FALSE;
}

/* test */

static void test_connection_refused(void)
{
	test_begin("connection refused");
	test_expect_error_string("Connection refused");
	test_run_client_server(test_client_connection_refused,
			       test_server_connection_refused);
	test_end();
}

/*
 * Connection timed out
 */

/* server */

static void test_connection_timed_out_input(struct server_connection *conn)
{
	i_sleep_intr_secs(5);
	server_connection_deinit(&conn);
}

static void test_server_connection_timed_out(void)
{
	test_server_input = test_connection_timed_out_input;
	test_server_run();
}

/* client */

static bool test_client_connection_timed_out(void)
{
	time_t time;
	const char *error;
	int ret;

	io_loop_time_refresh();
	time = ioloop_time;

	ret = test_client_auth_simple("PLAIN", "harrie", "frop", FALSE, &error);
	test_out_reason("run (ret == -1)", ret == -1, error);

	io_loop_time_refresh();
	test_out("timeout", (ioloop_time - time) < 5);
	return FALSE;
}

/* test */

static void test_connection_timed_out(void)
{
	test_begin("connection timed out");
	test_expect_error_string("Timeout waiting for handshake");
	test_run_client_server(test_client_connection_timed_out,
			       test_server_connection_timed_out);
	test_end();
}

/*
 * Bad VERSION
 */

/* server */

static void test_bad_version_input(struct server_connection *conn)
{
	server_connection_deinit(&conn);
}

static void test_bad_version_init(struct server_connection *conn)
{
	o_stream_nsend_str(
		conn->conn.output,
		"VERSION\t666\t666\n"
		"MECH\tPLAIN\tplaintext\n"
		"MECH\tLOGIN\tplaintext\n"
		"SPID\t12296\n"
		"CUID\t2\n"
		"COOKIE\t46cc85ccd2833ca39a49c059fa3d3ccf\n"
		"DONE\n");
}

static void test_server_bad_version(void)
{
	test_server_init = test_bad_version_init;
	test_server_input = test_bad_version_input;
	test_server_run();
}

/* client */

static bool test_client_bad_version(void)
{
	const char *error;
	int ret;

	ret = test_client_auth_simple("PLAIN", "harrie", "frop", FALSE, &error);
	test_out_reason("run (ret == -1)", ret == -1, error);
	return FALSE;
}

/* test */

static void test_bad_version(void)
{
	test_begin("bad version");
	test_expect_error_string("Socket supports major version 666");
	test_run_client_server(test_client_bad_version,
			       test_server_bad_version);
	test_end();
}

/*
 * Disconnect VERSION
 */

/* server */

static void test_disconnect_version_input(struct server_connection *conn)
{
	const char *line;

	line = i_stream_read_next_line(conn->conn.input);
	if (line == NULL) {
		if (conn->conn.input->eof)
			server_connection_deinit(&conn);
		return;
	}
	server_connection_deinit(&conn);
}

static void test_disconnect_version_init(struct server_connection *conn)
{
	o_stream_nsend_str(
		conn->conn.output,
		"VERSION\t1\t2\n"
		"MECH\tPLAIN\tplaintext\n"
		"MECH\tLOGIN\tplaintext\n"
		"SPID\t12296\n"
		"CUID\t2\n"
		"COOKIE\t46cc85ccd2833ca39a49c059fa3d3ccf\n"
		"DONE\n");
}

static void test_server_disconnect_version(void)
{
	test_server_init = test_disconnect_version_init;
	test_server_input = test_disconnect_version_input;
	test_server_run();
}

/* client */

static bool test_client_disconnect_version(void)
{
	const char *error;
	int ret;

	ret = test_client_auth_simple("PLAIN", "harrie", "frop", FALSE, &error);
	test_out_reason("run (ret == -1)", ret == -1, error);
	return FALSE;
}

/* test */

static void test_disconnect_version(void)
{
	test_begin("disconnect version");
	test_expect_errors(2);
	test_run_client_server(test_client_disconnect_version,
			       test_server_disconnect_version);
	test_end();
}

/*
 * Auth handshake
 */

/* server */

enum _auth_handshake_state {
	AUTH_HANDSHAKE_STATE_VERSION = 0,
	AUTH_HANDSHAKE_STATE_CMD
};

struct _auth_handshake_request {
	struct _auth_handshake_request *prev, *next;

	unsigned int id;
	const char *username;

	unsigned int login_state;
};

struct _auth_handshake_server {
	enum _auth_handshake_state state;

	struct _auth_handshake_request *requests;
};

static bool
test_auth_handshake_auth_plain(struct server_connection *conn, unsigned int id,
			       const unsigned char *data, size_t data_size)
{
	const char *authid, *authenid;
	const char *pass;
	size_t i, len;
	int count;

	/* authorization ID \0 authentication ID \0 pass. */
	authid = (const char *) data;
	authenid = NULL; pass = NULL;

	count = 0;
	for (i = 0; i < data_size; i++) {
		if (data[i] == '\0') {
			if (++count == 1)
				authenid = (const char *)data + (i + 1);
			else {
				i++;
				len = data_size - i;
				pass = t_strndup(data+i, len);
				break;
			}
		}
	}

	if (count != 2) {
		i_error("Bad AUTH PLAIN request: Bad data");
		return FALSE;
	}

	if (authenid == NULL)
		authenid = authid;
	if (strcmp(authenid, "harrie") == 0 && strcmp(pass, "frop") == 0) {
		o_stream_nsend_str(
			conn->conn.output,
			t_strdup_printf("OK\t%u\tuser=harrie\n", id));
		return TRUE;
	}
	if (strcmp(authenid, "hendrik") == 0)
		return FALSE;
	o_stream_nsend_str(
		conn->conn.output,
		t_strdup_printf("FAIL\t%u\tuser=%s\n", id, authenid));

	return TRUE;
}

static bool
test_auth_handshake_auth_login(struct server_connection *conn, unsigned int id,
			       const unsigned char *data ATTR_UNUSED,
			       size_t data_size)
{
	static const char *prompt1 = "Username:";
	struct _auth_handshake_server *ctx =
		(struct _auth_handshake_server *)conn->context;
	struct _auth_handshake_request *req;
	string_t *chal_b64;

	if (data_size != 0) {
		i_error("Bad AUTH PLAIN request: "
			"Not expecting initial response");
		return FALSE;
	}

	req = p_new(conn->pool, struct _auth_handshake_request, 1);
	req->id = id;
	DLLIST_PREPEND(&ctx->requests, req);

	chal_b64 = t_str_new(64);
	base64_encode(prompt1, strlen(prompt1), chal_b64);
	o_stream_nsend_str(
		conn->conn.output,
		t_strdup_printf("CONT\t%u\t%s\n", id, str_c(chal_b64)));
	return TRUE;
}

static bool
test_auth_handshake_cont_login(struct server_connection *conn,
			       struct _auth_handshake_request *req,
			       const unsigned char *data, size_t data_size)
{
	static const char *prompt2 = "Password:";
	struct _auth_handshake_server *ctx =
		(struct _auth_handshake_server *)conn->context;
	const char *resp = t_strndup(data, data_size);
	string_t *chal_b64;

	if (++req->login_state == 1) {
		req->username = p_strdup(conn->pool, resp);
		if (strcmp(resp, "harrie") != 0) {
			o_stream_nsend_str(
				conn->conn.output,
				t_strdup_printf("FAIL\t%u\tuser=%s\n",
						req->id, req->username));
			return TRUE;
		}
	} else {
		i_assert(req->login_state == 2);
		DLLIST_REMOVE(&ctx->requests, req);
		if (strcmp(resp, "frop") != 0) {
			o_stream_nsend_str(
				conn->conn.output,
				t_strdup_printf("FAIL\t%u\tuser=%s\n",
						req->id, req->username));
			return TRUE;
		}
		o_stream_nsend_str(
			conn->conn.output,
			t_strdup_printf("OK\t%u\tuser=harrie\n", req->id));
		return TRUE;
	}

	chal_b64 = t_str_new(64);
	base64_encode(prompt2, strlen(prompt2), chal_b64);
	o_stream_nsend_str(conn->conn.output,
			   t_strdup_printf("CONT\t%u\t%s\n",
					   req->id, str_c(chal_b64)));
	return TRUE;
}


static bool
test_auth_handshake_auth(struct server_connection *conn, unsigned int id,
			 const char *const *args)
{
	const char *mech, *resp;
	unsigned int i;
	buffer_t *data;

	if (args[0] == NULL) {
		i_error("Bad AUTH request");
		return FALSE;
	}
	mech = args[0];
	resp = NULL;
	for (i = 1; args[i] != NULL; i++) {
		if (str_begins(args[i], "resp=")) {
			resp = t_strdup(args[i] + 5);
			break;
		}
	}
	data = t_buffer_create(256);
	if (resp != NULL) {
		if (base64_decode(resp, strlen(resp), NULL, data) < 0) {
			i_error("Bad AUTH request: Bad base64");
			return FALSE;
		}
	}

	if (strcasecmp(mech, "PLAIN") == 0) {
		return test_auth_handshake_auth_plain(conn, id,
						      data->data, data->used);
	} else if (strcasecmp(mech, "LOGIN") == 0) {
		return test_auth_handshake_auth_login(conn, id,
						      data->data, data->used);
	}
	i_error("Bad AUTH request: Unknown mechanism");
	return FALSE;
}

static bool
test_auth_handshake_cont(struct server_connection *conn, unsigned int id,
			 const char *const *args)
{
	struct _auth_handshake_server *ctx =
		(struct _auth_handshake_server *)conn->context;
	struct _auth_handshake_request *req;
	const char *resp;
	buffer_t *data;

	if (args[0] == NULL) {
		i_error("Bad CONT request");
		return FALSE;
	}
	resp = args[0];
	data = t_buffer_create(256);
	if (resp != NULL) {
		if (base64_decode(resp, strlen(resp), NULL, data) < 0) {
			i_error("Bad CONT request: Bad base64");
			return FALSE;
		}
	}

	req = ctx->requests;
	while (req != NULL) {
		if (req->id == id)
			break;
		req = req->next;
	}

	if (req == NULL) {
		i_error("Bad CONT request: Bad request ID");
		return FALSE;
	}

	return test_auth_handshake_cont_login(conn, req,
					      data->data, data->used);
}

static void test_auth_handshake_input(struct server_connection *conn)
{
	struct _auth_handshake_server *ctx =
		(struct _auth_handshake_server *)conn->context;
	const char *const *args;
	unsigned int id;
	const char *line;

	for (;;) {
		line = i_stream_read_next_line(conn->conn.input);
		if (line == NULL) {
			if (conn->conn.input->eof)
				server_connection_deinit(&conn);
			return;
		}

		switch (ctx->state) {
		case AUTH_HANDSHAKE_STATE_VERSION:
			if (!str_begins(line, "VERSION\t")) {
				i_error("Bad VERSION");
				server_connection_deinit(&conn);
				return;
			}
			ctx->state = AUTH_HANDSHAKE_STATE_CMD;
			continue;
		case AUTH_HANDSHAKE_STATE_CMD:
			args = t_strsplit_tabescaped(line);
			if (args[0] == NULL || args[1] == NULL) {
				i_error("Bad request");
				server_connection_deinit(&conn);
				return;
			}
			if (str_to_uint(args[1], &id) < 0) {
				i_error("Bad %s request", args[0]);
				server_connection_deinit(&conn);
				return;
			}

			if (strcmp(args[0], "CPID") == 0) {
				continue;
			} else  if (strcmp(args[0], "AUTH") == 0) {
				if (test_auth_handshake_auth(conn, id,
							     args + 2))
					continue;
			} else  if (strcmp(args[0], "CONT") == 0) {
				if (test_auth_handshake_cont(conn, id,
							     args + 2))
					continue;
			} else {
				i_error("Bad request: %s", args[0]);
				server_connection_deinit(&conn);
				return;
			}
			server_connection_deinit(&conn);
			return;
		}
		i_unreached();
	}
}

static void test_auth_handshake_init(struct server_connection *conn)
{
	struct _auth_handshake_server *ctx;

	ctx = p_new(conn->pool, struct _auth_handshake_server, 1);
	conn->context = (void*)ctx;

	o_stream_nsend_str(
		conn->conn.output,
		"VERSION\t1\t2\n"
		"MECH\tPLAIN\tplaintext\n"
		"MECH\tLOGIN\tplaintext\n"
		"SPID\t12296\n"
		"CUID\t2\n"
		"COOKIE\t46cc85ccd2833ca39a49c059fa3d3ccf\n"
		"DONE\n");
}

static void test_server_auth_handshake(void)
{
	test_server_init = test_auth_handshake_init;
	test_server_input = test_auth_handshake_input;
	test_server_run();
}

/* client */

static bool test_client_auth_plain_disconnect(void)
{
	const char *error;
	int ret;

	ret = test_client_auth_simple("PLAIN", "hendrik", "frop", FALSE,
				      &error);
	test_out("run (ret < 0)", ret < 0);
	test_assert(error != NULL && strstr(error, "Internal failure") != NULL);

	return FALSE;
}

static bool test_client_auth_plain_reconnect(void)
{
	const char *error;
	int ret;

	ret = test_client_auth_simple("PLAIN", "hendrik", "frop", TRUE,
				      &error);
	test_out("run (ret < 0)", ret < 0);
	test_assert(error != NULL && strstr(error, "Internal failure") != NULL);

	return FALSE;
}

static bool test_client_auth_plain_failure(void)
{
	const char *error;
	int ret;

	ret = test_client_auth_simple("PLAIN", "henk", "frop", FALSE, &error);
	test_out("run (ret < 0)", ret < 0);
	test_assert(error != NULL && strstr(error, "Login failure") != NULL);

	return FALSE;
}

static bool test_client_auth_plain_success(void)
{
	const char *error;
	int ret;

	ret = test_client_auth_simple("PLAIN", "harrie", "frop", FALSE, &error);
	test_out("run (ret == 0)", ret == 0);
	test_assert(error == NULL);

	return FALSE;
}

static bool test_client_auth_login_failure1(void)
{
	const char *error;
	int ret;

	ret = test_client_auth_simple("LOGIN", "henk", "frop", FALSE, &error);
	test_out("run (ret < 0)", ret < 0);
	test_assert(error != NULL && strstr(error, "Login failure") != NULL);

	return FALSE;
}

static bool test_client_auth_login_failure2(void)
{
	const char *error;
	int ret;

	ret = test_client_auth_simple("LOGIN", "harrie", "friep", FALSE,
				      &error);
	test_out("run (ret < 0)", ret < 0);
	test_assert(error != NULL && strstr(error, "Login failure") != NULL);

	return FALSE;
}

static bool test_client_auth_login_success(void)
{
	const char *error;
	int ret;

	ret = test_client_auth_simple("LOGIN", "harrie", "frop", FALSE, &error);
	test_out("run (ret == 0)", ret == 0);
	test_assert(error == NULL);

	return FALSE;
}

static bool test_client_auth_plain_parallel_failure(void)
{
	const char *error;
	int ret;

	ret = test_client_auth_parallel("PLAIN", "henk", "frop", 4, FALSE,
					&error);
	test_out("run (ret < 0)", ret < 0);
	test_assert(error != NULL && strstr(error, "Login failure") != NULL);

	return FALSE;
}

static bool test_client_auth_plain_parallel_success(void)
{
	const char *error;
	int ret;

	ret = test_client_auth_parallel("PLAIN", "harrie", "frop", 4, FALSE,
					&error);
	test_out("run (ret == 0)", ret == 0);
	test_assert(error == NULL);

	return FALSE;
}

static bool test_client_auth_login_parallel_failure1(void)
{
	const char *error;
	int ret;

	ret = test_client_auth_parallel("LOGIN", "henk", "frop", 4, FALSE,
					&error);
	test_out("run (ret < 0)", ret < 0);
	test_assert(error != NULL && strstr(error, "Login failure") != NULL);

	return FALSE;
}

static bool test_client_auth_login_parallel_failure2(void)
{
	const char *error;
	int ret;

	ret = test_client_auth_parallel("LOGIN", "harrie", "friep", 4, FALSE,
					&error);
	test_out("run (ret < 0)", ret < 0);
	test_assert(error != NULL && strstr(error, "Login failure") != NULL);

	return FALSE;
}

static bool test_client_auth_login_parallel_success(void)
{
	const char *error;
	int ret;

	ret = test_client_auth_parallel("LOGIN", "harrie", "frop", 4, FALSE,
					&error);
	test_out("run (ret == 0)", ret == 0);
	test_assert(error == NULL);

	return FALSE;
}

/* test */

static void test_auth_handshake(void)
{
	test_begin("auth PLAIN disconnect");
	test_expect_errors(1);
	test_run_client_server(test_client_auth_plain_disconnect,
			       test_server_auth_handshake);
	test_end();

	test_begin("auth PLAIN reconnect");
	test_expect_errors(2);
	test_run_client_server(test_client_auth_plain_reconnect,
			       test_server_auth_handshake);
	test_end();

	test_begin("auth PLAIN failure");
	test_run_client_server(test_client_auth_plain_failure,
			       test_server_auth_handshake);
	test_end();

	test_begin("auth PLAIN success");
	test_run_client_server(test_client_auth_plain_success,
			       test_server_auth_handshake);
	test_end();

	test_begin("auth LOGIN failure 1");
	test_run_client_server(test_client_auth_login_failure1,
			       test_server_auth_handshake);
	test_end();

	test_begin("auth LOGIN failure 2");
	test_run_client_server(test_client_auth_login_failure2,
			       test_server_auth_handshake);
	test_end();

	test_begin("auth LOGIN success");
	test_run_client_server(test_client_auth_login_success,
			       test_server_auth_handshake);
	test_end();

	test_begin("auth PLAIN parallel failure");
	test_run_client_server(test_client_auth_plain_parallel_failure,
			       test_server_auth_handshake);
	test_end();

	test_begin("auth PLAIN parallel success");
	test_run_client_server(test_client_auth_plain_parallel_success,
			       test_server_auth_handshake);
	test_end();

	test_begin("auth LOGIN parallel failure 1");
	test_run_client_server(test_client_auth_login_parallel_failure1,
			       test_server_auth_handshake);
	test_end();

	test_begin("auth LOGIN parallel failure 2");
	test_run_client_server(test_client_auth_login_parallel_failure2,
			       test_server_auth_handshake);
	test_end();

	test_begin("auth LOGIN parallel success");
	test_run_client_server(test_client_auth_login_parallel_success,
			       test_server_auth_handshake);
	test_end();
}

/*
 * All tests
 */

static void (*const test_functions[])(void) = {
	test_connection_refused,
	test_connection_timed_out,
	test_bad_version,
	test_disconnect_version,
	test_auth_handshake,
	NULL
};

/*
 * Test client
 */

struct timeout *to_client_progress = NULL;

static void test_client_deinit(void)
{
}

struct login_request {
	struct login_test *test;

	unsigned int state;
};

struct login_test {
	char *error;
	int status;

	const char *username;
	const char *password;

	unsigned int requests_pending;

	struct ioloop *ioloop;
};

static void
test_client_auth_callback(struct auth_client_request *request,
			  enum auth_request_status status,
			  const char *data_base64 ATTR_UNUSED,
			  const char *const *args ATTR_UNUSED, void *context)
{
	struct login_request *login_req = context;
	struct login_test *login_test = login_req->test;
	string_t *resp_b64;
	const char *errormsg = NULL;

	if (to_client_progress != NULL)
		timeout_reset(to_client_progress);

	switch (status) {
	case AUTH_REQUEST_STATUS_ABORT:
		errormsg = "Abort";
		break;
	case AUTH_REQUEST_STATUS_INTERNAL_FAIL:
		errormsg = "Internal failure";
		break;
	case AUTH_REQUEST_STATUS_FAIL:
		errormsg = "Login failure";
		break;
	case AUTH_REQUEST_STATUS_CONTINUE:
		resp_b64 = t_str_new(64);
		if (++login_req->state == 1) {
			base64_encode(login_test->username,
				      strlen(login_test->username), resp_b64);
		} else {
			test_assert(login_req->state == 2);
			base64_encode(login_test->password,
				      strlen(login_test->password), resp_b64);
		}
		auth_client_request_continue(request, str_c(resp_b64));
		return;
	case AUTH_REQUEST_STATUS_OK:
		break;
	}

	if (login_test->status == 0 && errormsg != NULL) {
		i_assert(login_test->error == NULL);
		login_test->error = i_strdup(errormsg);
		login_test->status = -1;
	}

	if (--login_test->requests_pending == 0)
		io_loop_stop(login_test->ioloop);
}

static void
test_client_auth_connected(struct auth_client *client ATTR_UNUSED,
			   bool connected, void *context)
{
	struct login_test *login_test = context;

	if (to_client_progress != NULL)
		timeout_reset(to_client_progress);

	if (login_test->status == 0 && !connected) {
		i_assert(login_test->error == NULL);
		login_test->error = i_strdup("Connection failed");
		login_test->status = -1;
	}
	io_loop_stop(login_test->ioloop);
}

static void test_client_progress_timeout(void *context ATTR_UNUSED)
{
	/* Terminate test due to lack of progress */
	test_assert(FALSE);
	timeout_remove(&to_client_progress);
	io_loop_stop(current_ioloop);
}

static int
test_client_auth_run(struct auth_client *auth_client, struct ioloop *ioloop,
		     struct auth_request_info *info,
		     const char *username, const char *password,
		     unsigned int concurrency, const char **error_r)
{
	struct login_test login_test;
	struct login_request *login_reqs;
	unsigned int i;
	int ret;

	i_zero(&login_test);
	login_test.ioloop = ioloop;
	login_test.username = username;
	login_test.password = password;

	auth_client_set_connect_timeout(auth_client, 1000);
	auth_client_connect(auth_client);
	if (auth_client_is_disconnected(auth_client)) {
		login_test.error = i_strdup("Connection failed");
		login_test.status = -1;
	} else {
		auth_client_set_connect_notify(
			auth_client, test_client_auth_connected, &login_test);
		io_loop_run(ioloop);
	}

	if (login_test.status >= 0) {
		io_loop_set_running(ioloop);
		login_test.requests_pending = concurrency;
		login_reqs = t_new(struct login_request, concurrency);
		for (i = 0; i < concurrency; i++) {
			login_reqs[i].test = &login_test;
			(void)auth_client_request_new(auth_client, info,
						      test_client_auth_callback,
						      &login_reqs[i]);
		}
		if (io_loop_is_running(ioloop))
			io_loop_run(ioloop);
	}

	ret = login_test.status;
	*error_r = t_strdup(login_test.error);

	i_free(login_test.error);
	auth_client_set_connect_notify(auth_client, NULL, NULL);

	return ret;
}

static int
test_client_auth_parallel(const char *mech, const char *username,
			  const char *password, unsigned int concurrency,
			  bool retry, const char **error_r)
{
	struct auth_client *auth_client;
	struct auth_request_info info;
	struct ioloop *ioloop;
	int ret;

	i_zero(&info);
	info.mech = mech;
	info.service = "test";
	info.session_id = "23423dfd243daaa223";
	info.flags = AUTH_REQUEST_FLAG_SECURED;

	(void)net_addr2ip("10.0.0.15", &info.local_ip);
	info.local_port = 143;
	(void)net_addr2ip("10.0.0.211", &info.remote_ip);
	info.remote_port = 45546;
	(void)net_addr2ip("10.1.0.54", &info.real_local_ip);
	info.real_local_port = 143;
	(void)net_addr2ip("10.1.0.221", &info.real_remote_ip);
	info.real_remote_port = 23246;

	if (strcasecmp(mech, "PLAIN") == 0) {
		string_t *resp_b64, *resp;

		resp = t_str_new(64);
		str_append(resp, "supremelordoftheuniverse");
		str_append_c(resp, '\0');
		str_append(resp, username);
		str_append_c(resp, '\0');
		str_append(resp, password);

		resp_b64 = t_str_new(64);
		base64_encode(str_data(resp), str_len(resp), resp_b64);
		info.initial_resp_base64 = str_c(resp_b64);
	} else if (strcasecmp(mech, "LOGIN") == 0) {
		/* no intial response */
	} else {
		i_unreached();
	}

	ioloop = io_loop_create();
	to_client_progress = timeout_add(CLIENT_PROGRESS_TIMEOUT*1000,
					 test_client_progress_timeout, NULL);

	auth_client = auth_client_init(TEST_SOCKET, 2234, debug);
	ret = test_client_auth_run(auth_client, ioloop, &info,
				   username, password, concurrency,
				   error_r);
	if (ret < 0 && retry) {
		ret = test_client_auth_run(auth_client, ioloop, &info,
					   username, password, concurrency,
					   error_r);
	}
	auth_client_deinit(&auth_client);

	timeout_remove(&to_client_progress);
	io_loop_destroy(&ioloop);

	return ret;
}

static int
test_client_auth_simple(const char *mech, const char *username,
			const char *password, bool retry, const char **error_r)
{
	return test_client_auth_parallel(mech, username, password, 1, retry,
					 error_r);
}

/*
 * Test server
 */

/* client connection */

static void server_connection_input(struct connection *_conn)
{
	struct server_connection *conn = (struct server_connection *)_conn;

	test_server_input(conn);
}

static void server_connection_init(int fd)
{
	struct server_connection *conn;
	pool_t pool;

	net_set_nonblock(fd, TRUE);

	pool = pool_alloconly_create("server connection", 256);
	conn = p_new(pool, struct server_connection, 1);
	conn->pool = pool;

	connection_init_server(server_conn_list, &conn->conn,
			       "server connection", fd, fd);

	if (test_server_init != NULL)
		test_server_init(conn);
}

static void server_connection_deinit(struct server_connection **_conn)
{
	struct server_connection *conn = *_conn;

	*_conn = NULL;

	if (test_server_deinit != NULL)
		test_server_deinit(conn);

	connection_deinit(&conn->conn);
	pool_unref(&conn->pool);
}

static void server_connection_destroy(struct connection *_conn)
{
	struct server_connection *conn = (struct server_connection *)_conn;

	server_connection_deinit(&conn);
}

static void server_connection_accept(void *context ATTR_UNUSED)
{
	int fd;

	/* accept new client */
	fd = net_accept(fd_listen, NULL, NULL);
	if (fd == -1)
		return;
	if (fd == -2)
		i_fatal("test server: accept() failed: %m");

	server_connection_init(fd);
}

/* */

static struct connection_settings server_connection_set = {
	.input_max_size = SIZE_MAX,
	.output_max_size = SIZE_MAX,
	.client = FALSE
};

static const struct connection_vfuncs server_connection_vfuncs = {
	.destroy = server_connection_destroy,
	.input = server_connection_input
};

static void test_server_run(void)
{
	/* open server socket */
	io_listen = io_add(fd_listen, IO_READ, server_connection_accept, NULL);

	server_conn_list = connection_list_init(&server_connection_set,
						&server_connection_vfuncs);

	io_loop_run(ioloop);

	/* close server socket */
	io_remove(&io_listen);

	connection_list_deinit(&server_conn_list);
}

/*
 * Tests
 */

static int test_open_server_fd(void)
{
	int fd;
	i_unlink_if_exists(TEST_SOCKET);
	fd = net_listen_unix(TEST_SOCKET, 128);
	if (debug)
		i_debug("server listening on "TEST_SOCKET);
	if (fd == -1)
		i_fatal("listen("TEST_SOCKET") failed: %m");
	return fd;
}

static int test_run_server(test_server_init_t *server_test)
{
	main_deinit();
	master_service_deinit_forked(&master_service);

	i_set_failure_prefix("SERVER: ");

	if (debug)
		i_debug("PID=%s", my_pid);

	ioloop = io_loop_create();
	server_test();
	io_loop_destroy(&ioloop);

	if (debug)
		i_debug("Terminated");

	i_close_fd(&fd_listen);
	return 0;
}

static void test_run_client(test_client_init_t *client_test)
{
	i_set_failure_prefix("CLIENT: ");

	if (debug)
		i_debug("PID=%s", my_pid);

	i_sleep_intr_msecs(100); /* wait a little for server setup */

	ioloop = io_loop_create();
	if (client_test())
		io_loop_run(ioloop);
	test_client_deinit();
	io_loop_destroy(&ioloop);

	if (debug)
		i_debug("Terminated");
}

static void
test_run_client_server(test_client_init_t *client_test,
		       test_server_init_t *server_test)
{
	if (server_test != NULL) {
		/* Fork server */
		fd_listen = test_open_server_fd();
		test_subprocess_fork(test_run_server, server_test, FALSE);
		i_close_fd(&fd_listen);
	}

	/* Run client */
	test_run_client(client_test);

	i_unset_failure_prefix();
	test_subprocess_kill_all(SERVER_KILL_TIMEOUT_SECS);
}

/*
 * Main
 */

static void main_cleanup(void)
{
	i_unlink_if_exists(TEST_SOCKET);
}

static void main_init(void)
{
	/* nothing yet */
}

static void main_deinit(void)
{
	/* nothing yet; also called from sub-processes */
}

int main(int argc, char *argv[])
{
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_STANDALONE |
		MASTER_SERVICE_FLAG_DONT_SEND_STATS |
		MASTER_SERVICE_FLAG_NO_SSL_INIT;
	int c;
	int ret;

	master_service = master_service_init("test-auth-master", service_flags,
					     &argc, &argv, "D");
	main_init();

	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'D':
			debug = TRUE;
			break;
		default:
			i_fatal("Usage: %s [-D]", argv[0]);
		}
	}

	master_service_init_finish(master_service);
	test_subprocesses_init(debug);
	test_subprocess_set_cleanup_callback(main_cleanup);

	ret = test_run(test_functions);

	test_subprocesses_deinit();
	main_deinit();
	master_service_deinit(&master_service);

	return ret;
}
