/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "network.h"
#include "array.h"
#include "str.h"
#include "str-sanitize.h"
#include "safe-memset.h"
#include "auth-stream.h"
#include "auth-request-handler.h"
#include "auth-client-interface.h"
#include "auth-client-connection.h"
#include "auth-master-listener.h"
#include "auth-master-connection.h"

#include <stdlib.h>

#define OUTBUF_THROTTLE_SIZE (1024*50)

static void auth_client_connection_unref(struct auth_client_connection **_conn);

static void auth_client_input(struct auth_client_connection *conn);

static const char *reply_line_hide_pass(const char *line)
{
	const char *p, *p2;

	/* hide proxy reply password */
	p = strstr(line, "\tpass=");
	if (p == NULL)
		return line;
	p += 6;

	p2 = strchr(p, '\t');
	return t_strconcat(t_strdup_until(line, p), PASSWORD_HIDDEN_STR,
			   p2, NULL);
}

static void auth_client_send(struct auth_client_connection *conn,
			     const char *cmd)
{
	struct const_iovec iov[2];

	iov[0].iov_base = cmd;
	iov[0].iov_len = strlen(cmd);
	iov[1].iov_base = "\n";
	iov[1].iov_len = 1;
	(void)o_stream_sendv(conn->output, iov, 2);

	if (o_stream_get_buffer_used_size(conn->output) >=
	    OUTBUF_THROTTLE_SIZE) {
		/* stop reading new requests until client has read the pending
		   replies. */
		if (conn->io != NULL)
			io_remove(&conn->io);
	}

	if (conn->auth->verbose_debug) {
		i_info("client out: %s", conn->auth->verbose_debug_passwords ?
		       cmd : reply_line_hide_pass(cmd));
	}
}

static void auth_callback(struct auth_stream_reply *reply,
			  struct auth_client_connection *conn)
{
	if (reply == NULL) {
		/* handler destroyed */
		auth_client_connection_unref(&conn);
		return;
	}

	auth_client_send(conn, auth_stream_reply_export(reply));
}

static bool
auth_client_input_cpid(struct auth_client_connection *conn, const char *args)
{
        struct auth_client_connection *old;
	unsigned int pid;

	i_assert(conn->pid == 0);

	pid = (unsigned int)strtoul(args, NULL, 10);
	if (pid == 0) {
		i_error("BUG: Authentication client said it's PID 0");
		return FALSE;
	}

	old = auth_client_connection_lookup(conn->listener, pid);
	if (old != NULL) {
		/* already exists. it's possible that it just reconnected,
		   see if the old connection is still there. */
		i_assert(old != conn);
		if (i_stream_read(old->input) == -1) {
                        auth_client_connection_destroy(&old);
			old = NULL;
		}
	}

	if (old != NULL) {
		i_error("BUG: Authentication client gave a PID "
			"%u of existing connection", pid);
		return FALSE;
	}

	/* handshake complete, we can now actually start serving requests */
        conn->refcount++;
	conn->request_handler =
		auth_request_handler_create(conn->auth,
			auth_callback, conn,
			array_count(&conn->listener->masters) != 0 ?
			auth_master_request_callback : NULL);
	auth_request_handler_set(conn->request_handler, conn->connect_uid, pid);

	conn->pid = pid;
	if (conn->auth->verbose_debug)
		i_info("new auth connection: pid=%u", conn->pid);
	return TRUE;
}

static int auth_client_output(struct auth_client_connection *conn)
{
	if (o_stream_flush(conn->output) < 0) {
		auth_client_connection_destroy(&conn);
		return 1;
	}

	if (o_stream_get_buffer_used_size(conn->output) <=
	    OUTBUF_THROTTLE_SIZE/3 && conn->io == NULL) {
		/* allow input again */
		conn->io = io_add(conn->fd, IO_READ, auth_client_input, conn);
	}
	return 1;
}

static const char *auth_line_hide_pass(const char *line)
{
	const char *p, *p2;

	p = strstr(line, "\tresp=");
	if (p == NULL)
		return line;
	p += 6;

	p2 = strchr(p, '\t');
	return t_strconcat(t_strdup_until(line, p), PASSWORD_HIDDEN_STR,
			   p2, NULL);
}

static const char *cont_line_hide_pass(const char *line)
{
	const char *p;

	p = strchr(line, '\t');
	if (p == NULL)
		return line;

	return t_strconcat(t_strdup_until(line, p), PASSWORD_HIDDEN_STR, NULL);
}

static bool
auth_client_handle_line(struct auth_client_connection *conn, const char *line)
{
	if (strncmp(line, "AUTH\t", 5) == 0) {
		if (conn->auth->verbose_debug) {
			i_info("client in: %s",
			       conn->auth->verbose_debug_passwords ? line :
			       auth_line_hide_pass(line));
		}
		return auth_request_handler_auth_begin(conn->request_handler,
						       line + 5);
	}
	if (strncmp(line, "CONT\t", 5) == 0) {
		if (conn->auth->verbose_debug) {
			i_info("client in: %s",
			       conn->auth->verbose_debug_passwords ? line :
			       cont_line_hide_pass(line));
		}
		return auth_request_handler_auth_continue(conn->request_handler,
							  line + 5);
	}

	i_error("BUG: Authentication client sent unknown command: %s",
		str_sanitize(line, 80));
	return FALSE;
}

static void auth_client_input(struct auth_client_connection *conn)
{
	char *line;
	bool ret;

	switch (i_stream_read(conn->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		auth_client_connection_destroy(&conn);
		return;
	case -2:
		/* buffer full */
		i_error("BUG: Auth client %u sent us more than %d bytes",
			conn->pid, (int)AUTH_CLIENT_MAX_LINE_LENGTH);
		auth_client_connection_destroy(&conn);
		return;
	}

	while (conn->request_handler == NULL) {
		/* still handshaking */
		line = i_stream_next_line(conn->input);
		if (line == NULL)
			return;

		if (!conn->version_received) {
			/* make sure the major version matches */
			if (strncmp(line, "VERSION\t", 8) != 0 ||
			    atoi(t_strcut(line + 8, '\t')) !=
			    AUTH_CLIENT_PROTOCOL_MAJOR_VERSION) {
				i_error("Authentication client "
					"not compatible with this server "
					"(mixed old and new binaries?)");
				auth_client_connection_destroy(&conn);
				return;
			}
			conn->version_received = TRUE;
			continue;
		}

		if (strncmp(line, "CPID\t", 5) == 0) {
			if (!auth_client_input_cpid(conn, line + 5)) {
				auth_client_connection_destroy(&conn);
				return;
			}
		} else {
			i_error("BUG: Authentication client sent "
				"unknown handshake command: %s",
				str_sanitize(line, 80));
			auth_client_connection_destroy(&conn);
			return;
		}
	}

        conn->refcount++;
	while ((line = i_stream_next_line(conn->input)) != NULL) {
		T_BEGIN {
			ret = auth_client_handle_line(conn, line);
			safe_memset(line, 0, strlen(line));
		} T_END;

		if (!ret) {
			struct auth_client_connection *tmp_conn = conn;
			auth_client_connection_destroy(&tmp_conn);
			break;
		}
	}
	auth_client_connection_unref(&conn);
}

struct auth_client_connection *
auth_client_connection_create(struct auth_master_listener *listener, int fd)
{
	static unsigned int connect_uid_counter = 0;
	struct auth_client_connection *conn;
	struct const_iovec iov[2];
	string_t *str;

	conn = i_new(struct auth_client_connection, 1);
	conn->auth = listener->auth;
	conn->listener = listener;
	conn->refcount = 1;
	conn->connect_uid = ++connect_uid_counter;

	conn->fd = fd;
	conn->input = i_stream_create_fd(fd, AUTH_CLIENT_MAX_LINE_LENGTH,
					 FALSE);
	conn->output = o_stream_create_fd(fd, (size_t)-1, FALSE);
	o_stream_set_flush_callback(conn->output, auth_client_output, conn);
	conn->io = io_add(fd, IO_READ, auth_client_input, conn);

	array_append(&listener->clients, &conn, 1);

	str = t_str_new(128);
	str_printfa(str, "VERSION\t%u\t%u\nSPID\t%u\nCUID\t%u\nDONE\n",
                    AUTH_CLIENT_PROTOCOL_MAJOR_VERSION,
                    AUTH_CLIENT_PROTOCOL_MINOR_VERSION,
		    listener->pid, conn->connect_uid);

	iov[0].iov_base = str_data(conn->auth->mech_handshake);
	iov[0].iov_len = str_len(conn->auth->mech_handshake);
	iov[1].iov_base = str_data(str);
	iov[1].iov_len = str_len(str);

	if (o_stream_sendv(conn->output, iov, 2) < 0)
		auth_client_connection_destroy(&conn);

	return conn;
}

void auth_client_connection_destroy(struct auth_client_connection **_conn)
{
        struct auth_client_connection *conn = *_conn;
	struct auth_client_connection *const *clients;
	unsigned int i, count;

	*_conn = NULL;
	if (conn->fd == -1)
		return;

	clients = array_get(&conn->listener->clients, &count);
	for (i = 0; i < count; i++) {
		if (clients[i] == conn) {
			array_delete(&conn->listener->clients, i, 1);
			break;
		}
	}

	i_stream_close(conn->input);
	o_stream_close(conn->output);

	if (conn->io != NULL)
		io_remove(&conn->io);

	net_disconnect(conn->fd);
	conn->fd = -1;

	if (conn->request_handler != NULL)
		auth_request_handler_unref(&conn->request_handler);

        auth_client_connection_unref(&conn);
}

static void auth_client_connection_unref(struct auth_client_connection **_conn)
{
        struct auth_client_connection *conn = *_conn;

	*_conn = NULL;
	if (--conn->refcount > 0)
		return;

	i_stream_unref(&conn->input);
	o_stream_unref(&conn->output);
	i_free(conn);
}

struct auth_client_connection *
auth_client_connection_lookup(struct auth_master_listener *listener,
			      unsigned int pid)
{
	struct auth_client_connection *const *clients;
	unsigned int i, count;

	clients = array_get(&listener->clients, &count);
	for (i = 0; i < count; i++) {
		if (clients[i]->pid == pid)
			return clients[i];
	}

	return NULL;
}

static void request_timeout(struct auth_master_listener *listener)
{
	struct auth_client_connection *const *clients;
	unsigned int i, count;

	clients = array_get(&listener->clients, &count);
	for (i = 0; i < count; i++) {
		if (clients[i]->request_handler != NULL) {
			auth_request_handler_check_timeouts(
				clients[i]->request_handler);
		}
	}
}

void auth_client_connections_init(struct auth_master_listener *listener)
{
	listener->to_clients = timeout_add(5000, request_timeout, listener);
}

void auth_client_connections_deinit(struct auth_master_listener *listener)
{
	if (listener->to_clients != NULL)
		timeout_remove(&listener->to_clients);
}