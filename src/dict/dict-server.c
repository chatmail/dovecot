/* Copyright (c) 2005-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "dict.h"
#include "dict-client.h"
#include "dict-server.h"

#include <stdlib.h>
#include <unistd.h>

#define DICT_OUTPUT_OPTIMAL_SIZE 1024

struct dict_server_transaction {
	unsigned int id;
	struct dict_client_connection *conn;
	struct dict_transaction_context *ctx;
};

struct dict_client_connection {
	struct dict_client_connection *prev, *next;
	struct dict_server *server;

	char *username;
	char *name;
	struct dict *dict;
	enum dict_data_type value_type;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	struct dict_iterate_context *iter_ctx;

	/* There are only a few transactions per client, so keeping them in
	   array is fast enough */
	ARRAY_DEFINE(transactions, struct dict_server_transaction);
};

struct dict_server {
	char *path;
	int fd;
	struct io *io;

	struct dict_client_connection *connections;
};

struct dict_client_cmd {
	int cmd;
	int (*func)(struct dict_client_connection *conn, const char *line);
};

static void dict_client_connection_deinit(struct dict_client_connection *conn);

static int cmd_lookup(struct dict_client_connection *conn, const char *line)
{
	const char *reply;
	const char *value;
	int ret;

	if (conn->iter_ctx != NULL) {
		i_error("dict client: LOOKUP: Can't lookup while iterating");
		return -1;
	}

	/* <key> */
	ret = dict_lookup(conn->dict, pool_datastack_create(), line, &value);
	if (ret > 0) {
		reply = t_strdup_printf("%c%s\n",
					DICT_PROTOCOL_REPLY_OK, value);
		o_stream_send_str(conn->output, reply);
	} else {
		reply = t_strdup_printf("%c\n", ret == 0 ?
					DICT_PROTOCOL_REPLY_NOTFOUND :
					DICT_PROTOCOL_REPLY_FAIL);
		o_stream_send_str(conn->output, reply);
	}
	return 0;
}

static int cmd_iterate_flush(struct dict_client_connection *conn)
{
	string_t *str;
	const char *key, *value;
	int ret;

	str = t_str_new(256);
	o_stream_cork(conn->output);
	while ((ret = dict_iterate(conn->iter_ctx, &key, &value)) > 0) {
		str_truncate(str, 0);
		str_printfa(str, "%c%s\t%s\n", DICT_PROTOCOL_REPLY_OK,
			    key, value);
		o_stream_send(conn->output, str_data(str), str_len(str));

		if (o_stream_get_buffer_used_size(conn->output) >
		    DICT_OUTPUT_OPTIMAL_SIZE) {
			if (o_stream_flush(conn->output) <= 0)
				break;
			/* flushed everything, continue */
		}
	}

	if (ret <= 0) {
		/* finished iterating */
		o_stream_unset_flush_callback(conn->output);
		dict_iterate_deinit(&conn->iter_ctx);
		o_stream_send(conn->output, "\n", 1);
	}
	o_stream_uncork(conn->output);
	return ret <= 0 ? 1 : 0;
}

static int cmd_iterate(struct dict_client_connection *conn, const char *line)
{
	const char *const *args;

	if (conn->iter_ctx != NULL) {
		i_error("dict client: ITERATE: Already iterating");
		return -1;
	}

	args = t_strsplit(line, "\t");
	if (str_array_length(args) != 2) {
		i_error("dict client: ITERATE: broken input");
		return -1;
	}

	/* <flags> <path> */
	conn->iter_ctx = dict_iterate_init(conn->dict, args[1], atoi(args[0]));

	o_stream_set_flush_callback(conn->output, cmd_iterate_flush, conn);
	cmd_iterate_flush(conn);
	return 0;
}

static struct dict_server_transaction *
dict_server_transaction_lookup(struct dict_client_connection *conn,
			       unsigned int id)
{
	struct dict_server_transaction *transactions;
	unsigned int i, count;

	if (!array_is_created(&conn->transactions))
		return NULL;

	transactions = array_get_modifiable(&conn->transactions, &count);
	for (i = 0; i < count; i++) {
		if (transactions[i].id == id)
			return &transactions[i];
	}
	return NULL;
}

static void
dict_server_transaction_array_remove(struct dict_client_connection *conn,
				     struct dict_server_transaction *trans)
{
	const struct dict_server_transaction *transactions;
	unsigned int i, count;

	transactions = array_get(&conn->transactions, &count);
	for (i = 0; i < count; i++) {
		if (&transactions[i] == trans) {
			array_delete(&conn->transactions, i, 1);
			break;
		}
	}
}

static int cmd_begin(struct dict_client_connection *conn, const char *line)
{
	struct dict_server_transaction *trans;
	unsigned int id;

	if (!is_numeric(line, '\0')) {
		i_error("dict client: Invalid transaction ID %s", line);
		return -1;
	}

	id = (unsigned int)strtoul(line, NULL, 10);
	if (dict_server_transaction_lookup(conn, id) != NULL) {
		i_error("dict client: Transaction ID %u already exists", id);
		return -1;
	}

	if (!array_is_created(&conn->transactions))
		i_array_init(&conn->transactions, 4);

	/* <id> */
	trans = array_append_space(&conn->transactions);
	trans->id = id;
	trans->conn = conn;
	trans->ctx = dict_transaction_begin(conn->dict);
	return 0;
}

static int
dict_server_transaction_lookup_parse(struct dict_client_connection *conn,
				     const char *line,
				     struct dict_server_transaction **trans_r)
{
	unsigned int id;

	if (!is_numeric(line, '\0')) {
		i_error("dict client: Invalid transaction ID %s", line);
		return -1;
	}

	id = (unsigned int)strtoul(line, NULL, 10);
	*trans_r = dict_server_transaction_lookup(conn, id);
	if (*trans_r == NULL) {
		i_error("dict client: Transaction ID %u doesn't exist", id);
		return -1;
	}
	return 0;
}

static int cmd_commit(struct dict_client_connection *conn, const char *line)
{
	struct dict_server_transaction *trans;
	char chr;
	int ret;

	if (conn->iter_ctx != NULL) {
		i_error("dict client: COMMIT: Can't commit while iterating");
		return -1;
	}

	if (dict_server_transaction_lookup_parse(conn, line, &trans) < 0)
		return -1;

	ret = dict_transaction_commit(&trans->ctx);
	switch (ret) {
	case 1:
		chr = DICT_PROTOCOL_REPLY_OK;
		break;
	case 0:
		chr = DICT_PROTOCOL_REPLY_NOTFOUND;
		break;
	default:
		chr = DICT_PROTOCOL_REPLY_FAIL;
		break;
	}
	o_stream_send_str(conn->output, t_strdup_printf("%c\n", chr));
	dict_server_transaction_array_remove(conn, trans);
	return 0;
}

static void cmd_commit_async_callback(int ret, void *context)
{
	struct dict_server_transaction *trans = context;
	const char *reply;
	char chr;

	switch (ret) {
	case 1:
		chr = DICT_PROTOCOL_REPLY_OK;
		break;
	case 0:
		chr = DICT_PROTOCOL_REPLY_NOTFOUND;
		break;
	default:
		chr = DICT_PROTOCOL_REPLY_FAIL;
		break;
	}
	reply = t_strdup_printf("%c%c%u\n", DICT_PROTOCOL_REPLY_ASYNC_COMMIT,
				chr, trans->id);
	o_stream_send_str(trans->conn->output, reply);

	dict_server_transaction_array_remove(trans->conn, trans);
}

static int
cmd_commit_async(struct dict_client_connection *conn, const char *line)
{
	struct dict_server_transaction *trans;

	if (conn->iter_ctx != NULL) {
		i_error("dict client: COMMIT: Can't commit while iterating");
		return -1;
	}

	if (dict_server_transaction_lookup_parse(conn, line, &trans) < 0)
		return -1;

	dict_transaction_commit_async(&trans->ctx, cmd_commit_async_callback,
				      trans);
	return 0;
}

static int cmd_rollback(struct dict_client_connection *conn, const char *line)
{
	struct dict_server_transaction *trans;

	if (dict_server_transaction_lookup_parse(conn, line, &trans) < 0)
		return -1;

	dict_transaction_rollback(&trans->ctx);
	dict_server_transaction_array_remove(conn, trans);
	return 0;
}

static int cmd_set(struct dict_client_connection *conn, const char *line)
{
	struct dict_server_transaction *trans;
	const char *const *args;

	/* <id> <key> <value> */
	args = t_strsplit(line, "\t");
	if (str_array_length(args) != 3) {
		i_error("dict client: SET: broken input");
		return -1;
	}

	if (dict_server_transaction_lookup_parse(conn, args[0], &trans) < 0)
		return -1;

        dict_set(trans->ctx, args[1], args[2]);
	return 0;
}

static int cmd_unset(struct dict_client_connection *conn, const char *line)
{
	struct dict_server_transaction *trans;
	const char *const *args;

	/* <id> <key> */
	args = t_strsplit(line, "\t");
	if (str_array_length(args) != 2) {
		i_error("dict client: UNSET: broken input");
		return -1;
	}

	if (dict_server_transaction_lookup_parse(conn, args[0], &trans) < 0)
		return -1;

        dict_unset(trans->ctx, args[1]);
	return 0;
}

static int cmd_atomic_inc(struct dict_client_connection *conn, const char *line)
{
	struct dict_server_transaction *trans;
	const char *const *args;
	long long arg;

	/* <id> <key> <diff> */
	args = t_strsplit(line, "\t");
	if (str_array_length(args) != 3) {
		i_error("dict client: ATOMIC_INC: broken input");
		return -1;
	}

	if (dict_server_transaction_lookup_parse(conn, args[0], &trans) < 0)
		return -1;

	if (*args[2] != '-')
		arg = (long long)strtoull(args[2], NULL, 10);
	else
		arg = -(long long)strtoull(args[2]+1, NULL, 10);
        dict_atomic_inc(trans->ctx, args[1], arg);
	return 0;
}

static struct dict_client_cmd cmds[] = {
	{ DICT_PROTOCOL_CMD_LOOKUP, cmd_lookup },
	{ DICT_PROTOCOL_CMD_ITERATE, cmd_iterate },
	{ DICT_PROTOCOL_CMD_BEGIN, cmd_begin },
	{ DICT_PROTOCOL_CMD_COMMIT, cmd_commit },
	{ DICT_PROTOCOL_CMD_COMMIT_ASYNC, cmd_commit_async },
	{ DICT_PROTOCOL_CMD_ROLLBACK, cmd_rollback },
	{ DICT_PROTOCOL_CMD_SET, cmd_set },
	{ DICT_PROTOCOL_CMD_UNSET, cmd_unset },
	{ DICT_PROTOCOL_CMD_ATOMIC_INC, cmd_atomic_inc },

	{ 0, NULL }
};

static int dict_client_parse_handshake(struct dict_client_connection *conn,
				       const char *line)
{
	const char *username, *name, *value_type;

	if (*line++ != DICT_PROTOCOL_CMD_HELLO)
		return -1;

	/* check major version */
	if (*line++ - '0' != DICT_CLIENT_PROTOCOL_MAJOR_VERSION ||
	    *line++ != '\t')
		return -1;

	/* skip minor version */
	while (*line != '\t' && *line != '\0') line++;

	if (*line++ != '\t')
		return -1;

	/* get value type */
	value_type = line;
	while (*line != '\t' && *line != '\0') line++;

	if (*line++ != '\t')
		return -1;
	conn->value_type = atoi(t_strdup_until(value_type, line - 1));

	/* get username */
	username = line;
	while (*line != '\t' && *line != '\0') line++;

	if (*line++ != '\t')
		return -1;
	conn->username = i_strdup_until(username, line - 1);

	/* the rest is dict name. since we're looking it with getenv(),
	   disallow all funny characters that might confuse it, just in case. */
	name = line;
	while (*line > ' ' && *line != '=') line++;

	if (*line != '\0')
		return -1;

	conn->name = i_strdup(name);
	return 0;
}

static int dict_client_dict_init(struct dict_client_connection *conn)
{
	const char *uri;

	uri = getenv(t_strconcat("DICT_", conn->name, NULL));
	if (uri == NULL) {
		i_error("dict client: Unconfigured dictionary name '%s'",
			conn->name);
		return -1;
	}

	conn->dict = dict_init(uri, conn->value_type, conn->username,
			       getenv("BASE_DIR"));
	if (conn->dict == NULL) {
		/* dictionary initialization failed */
		i_error("Failed to initialize dictionary '%s'", conn->name);
		return -1;
	}
	return 0;
}

static void dict_client_connection_input(struct dict_client_connection *conn)
{
	const char *line;
	unsigned int i;
	int ret;

	switch (i_stream_read(conn->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		dict_client_connection_deinit(conn);
		return;
	case -2:
		/* buffer full */
		i_error("dict client: Sent us more than %d bytes",
			(int)DICT_CLIENT_MAX_LINE_LENGTH);
		dict_client_connection_deinit(conn);
		return;
	}

	if (conn->username == NULL) {
		/* handshake not received yet */
		if ((line = i_stream_next_line(conn->input)) == NULL)
			return;

		if (dict_client_parse_handshake(conn, line) < 0) {
			i_error("dict client: Broken handshake");
			dict_client_connection_deinit(conn);
			return;
		}
		if (dict_client_dict_init(conn)) {
			dict_client_connection_deinit(conn);
			return;
		}
	}

	while ((line = i_stream_next_line(conn->input)) != NULL) {
		ret = 0;
		for (i = 0; cmds[i].cmd != '\0'; i++) {
			if (cmds[i].cmd == *line) {
				T_BEGIN {
					ret = cmds[i].func(conn, line + 1);
				} T_END;
				break;
			}
		}
		if (ret < 0) {
			dict_client_connection_deinit(conn);
			break;
		}
	}
}

static void dict_client_connection_deinit(struct dict_client_connection *conn)
{
	struct dict_server_transaction *transactions;
	unsigned int i, count;

	if (conn->prev == NULL)
		conn->server->connections = conn->next;
	else
		conn->prev->next = conn->next;
	if (conn->next != NULL)
		conn->next->prev = conn->prev;

	if (array_is_created(&conn->transactions)) {
		transactions = array_get_modifiable(&conn->transactions, &count);
		for (i = 0; i < count; i++)
			dict_transaction_rollback(&transactions[i].ctx);
		array_free(&conn->transactions);
	}

	if (conn->iter_ctx != NULL)
		dict_iterate_deinit(&conn->iter_ctx);

	io_remove(&conn->io);
	i_stream_destroy(&conn->input);
	o_stream_destroy(&conn->output);
	if (close(conn->fd) < 0)
		i_error("close(dict client) failed: %m");

	if (conn->dict != NULL)
		dict_deinit(&conn->dict);
	i_free(conn->name);
	i_free(conn->username);
	i_free(conn);
}

static struct dict_client_connection *
dict_client_connection_init(struct dict_server *server, int fd)
{
	struct dict_client_connection *conn;

	conn = i_new(struct dict_client_connection, 1);
	conn->server = server;
	conn->fd = fd;
	conn->input = i_stream_create_fd(fd, DICT_CLIENT_MAX_LINE_LENGTH,
					 FALSE);
	conn->output = o_stream_create_fd(fd, 128*1024, FALSE);
	conn->io = io_add(fd, IO_READ, dict_client_connection_input, conn);

	if (server->connections != NULL) {
		conn->next = server->connections;
		server->connections->prev = conn;
	}
	server->connections = conn;
	return conn;
}

static void dict_server_listener_accept(struct dict_server *server)
{
	int fd;

	fd = net_accept(server->fd, NULL, NULL);
	if (fd < 0) {
		if (fd < -1)
			i_error("accept(%s) failed: %m", server->path);
	} else {
		net_set_nonblock(fd, TRUE);
		dict_client_connection_init(server, fd);
	}
}

struct dict_server *dict_server_init(const char *path, int fd)
{
	struct dict_server *server;

	server = i_new(struct dict_server, 1);
	server->path = i_strdup(path);
	server->fd = fd != -1 ? fd :
		net_listen_unix_unlink_stale(path, 128);
	if (server->fd == -1) {
		if (errno == EADDRINUSE)
			i_fatal("Socket already exists: %s", path);
		else
			i_fatal("net_listen_unix(%s) failed: %m", path);
	}
	net_set_nonblock(server->fd, TRUE);

	server->io = io_add(server->fd, IO_READ,
			    dict_server_listener_accept, server);
	return server;
}

void dict_server_deinit(struct dict_server *server)
{
	while (server->connections != NULL)
		dict_client_connection_deinit(server->connections);

	io_remove(&server->io);
	if (close(server->fd) < 0)
		i_error("close(%s) failed: %m", server->path);
	i_free(server->path);
	i_free(server);
}