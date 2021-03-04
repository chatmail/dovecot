/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "aqueue.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "master-service.h"
#include "indexer-queue.h"
#include "worker-connection.h"

#include <unistd.h>

#define INDEXER_PROTOCOL_MAJOR_VERSION 1
#define INDEXER_PROTOCOL_MINOR_VERSION 0

#define INDEXER_MASTER_HANDSHAKE "VERSION\tindexer-master-worker\t1\t0\n"
#define INDEXER_WORKER_NAME "indexer-worker-master"

struct worker_connection {
	int refcount;

	char *socket_path;
	indexer_status_callback_t *callback;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	char *request_username;
	struct indexer_request *request;

	unsigned int process_limit;
	bool version_received:1;
};

struct worker_connection *
worker_connection_create(const char *socket_path,
			 indexer_status_callback_t *callback)
{
	struct worker_connection *conn;

	conn = i_new(struct worker_connection, 1);
	conn->refcount = 1;
	conn->socket_path = i_strdup(socket_path);
	conn->callback = callback;
	conn->fd = -1;
	return conn;
}

static void worker_connection_unref(struct worker_connection *conn)
{
	i_assert(conn->refcount > 0);
	if (--conn->refcount > 0)
		return;

	i_free(conn->socket_path);
	i_free(conn);
}

static void worker_connection_disconnect(struct worker_connection *conn)
{
	if (conn->fd != -1) {
		io_remove(&conn->io);
		i_stream_destroy(&conn->input);
		o_stream_destroy(&conn->output);

		if (close(conn->fd) < 0)
			i_error("close(%s) failed: %m", conn->socket_path);
		conn->fd = -1;
	}

	/* conn->callback() can try to destroy us */
	conn->refcount++;
	i_free_and_null(conn->request_username);
	worker_connection_unref(conn);
}

void worker_connection_destroy(struct worker_connection **_conn)
{
	struct worker_connection *conn = *_conn;

	*_conn = NULL;

	worker_connection_disconnect(conn);
	worker_connection_unref(conn);
}

static int
worker_connection_input_line(struct worker_connection *conn, const char *line)
{
	int percentage;
	/* return -1 -> error
	           0 -> request completed (100%)
	           1 -> request continues (<100%)
	 */
	int ret = 1;

	if (str_to_int(line, &percentage) < 0 ||
	    percentage < -1 || percentage > 100) {
		i_error("Invalid input from worker: %s", line);
		return -1;
	}

	/* is request finished */
	if (percentage < 0)
		ret = -1;
	else if (percentage == 100)
		ret = 0;

	conn->callback(percentage, conn);
	return ret;
}

static void worker_connection_input(struct worker_connection *conn)
{
	const char *line;

	if (i_stream_read(conn->input) < 0) {
		worker_connection_disconnect(conn);
		return;
	}

	if (!conn->version_received) {
		if ((line = i_stream_next_line(conn->input)) == NULL)
			return;

		if (!version_string_verify(line, INDEXER_WORKER_NAME,
				INDEXER_PROTOCOL_MAJOR_VERSION)) {
			i_error("Indexer worker not compatible with this master "
				"(mixed old and new binaries?)");
			worker_connection_disconnect(conn);
			return;
		}
		conn->version_received = TRUE;
	}
	if (conn->process_limit == 0) {
		if ((line = i_stream_next_line(conn->input)) == NULL)
			return;
		if (str_to_uint(line, &conn->process_limit) < 0 ||
		    conn->process_limit == 0) {
			i_error("Indexer worker sent invalid handshake: %s",
				line);
			worker_connection_disconnect(conn);
			return;
		}
	}

	while ((line = i_stream_next_line(conn->input)) != NULL) {
		if (worker_connection_input_line(conn, line) <= 0) {
			break;
		}
	}
}

int worker_connection_connect(struct worker_connection *conn)
{
	i_assert(conn->fd == -1);

	conn->fd = net_connect_unix(conn->socket_path);
	if (conn->fd == -1) {
		i_error("connect(%s) failed: %m", conn->socket_path);
		return -1;
	}
	conn->io = io_add(conn->fd, IO_READ, worker_connection_input, conn);
	conn->input = i_stream_create_fd(conn->fd, SIZE_MAX);
	conn->output = o_stream_create_fd(conn->fd, SIZE_MAX);
	o_stream_set_no_error_handling(conn->output, TRUE);
	o_stream_nsend_str(conn->output, INDEXER_MASTER_HANDSHAKE);
	return 0;
}

bool worker_connection_is_connected(struct worker_connection *conn)
{
	return conn->fd != -1;
}

bool worker_connection_get_process_limit(struct worker_connection *conn,
					 unsigned int *limit_r)
{
	if (conn->process_limit == 0)
		return FALSE;

	*limit_r = conn->process_limit;
	return TRUE;
}

void worker_connection_request(struct worker_connection *conn,
			       struct indexer_request *request,
			       void *context)
{
	i_assert(worker_connection_is_connected(conn));
	i_assert(context != NULL);
	i_assert(request->index || request->optimize);

	if (conn->request_username == NULL)
		conn->request_username = i_strdup(request->username);
	else {
		i_assert(strcmp(conn->request_username,
				request->username) == 0);
	}

	conn->request = request;

	T_BEGIN {
		string_t *str = t_str_new(128);

		str_append_tabescaped(str, request->username);
		str_append_c(str, '\t');
		str_append_tabescaped(str, request->mailbox);
		str_append_c(str, '\t');
		if (request->session_id != NULL)
			str_append_tabescaped(str, request->session_id);
		str_printfa(str, "\t%u\t", request->max_recent_msgs);
		if (request->index)
			str_append_c(str, 'i');
		if (request->optimize)
			str_append_c(str, 'o');
		str_append_c(str, '\n');
		o_stream_nsend(conn->output, str_data(str), str_len(str));
	} T_END;
}

bool worker_connection_is_busy(struct worker_connection *conn)
{
	return conn->request != NULL;
}

const char *worker_connection_get_username(struct worker_connection *conn)
{
	return conn->request_username;
}

struct indexer_request *
worker_connection_get_request(struct worker_connection *conn)
{
	return conn->request;
}
