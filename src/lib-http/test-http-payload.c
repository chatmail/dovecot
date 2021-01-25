/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "llist.h"
#include "path-util.h"
#include "hostpid.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "istream-crlf.h"
#include "iostream-temp.h"
#include "iostream-ssl.h"
#include "iostream-ssl-test.h"
#ifdef HAVE_OPENSSL
#include "iostream-openssl.h"
#endif
#include "connection.h"
#include "test-common.h"
#include "test-subprocess.h"
#include "http-url.h"
#include "http-request.h"
#include "http-server.h"
#include "http-client.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#define CLIENT_PROGRESS_TIMEOUT     30
#define SERVER_KILL_TIMEOUT_SECS    20

enum payload_handling {
	PAYLOAD_HANDLING_LOW_LEVEL,
	PAYLOAD_HANDLING_FORWARD,
	PAYLOAD_HANDLING_HANDLER,
};

static bool debug = FALSE;
static bool small_socket_buffers = FALSE;
static const char *failure = NULL;
static struct timeout *to_continue = NULL;
static bool files_finished = FALSE;
static bool running_continue = FALSE;

static struct test_settings {
	/* client */
	bool client_blocking;
	unsigned int max_pending;
	unsigned int client_ioloop_nesting;
	bool request_100_continue;
	unsigned int parallel_clients;
	bool parallel_clients_global;
	size_t read_client_partial;
	bool unknown_size;

	/* server */
	bool server_blocking;
	bool server_ostream;
	enum payload_handling server_payload_handling;
	size_t read_server_partial;
	bool server_cork;

	bool ssl;
} tset;

static struct ip_addr bind_ip;
static in_port_t bind_port = 0;
static int fd_listen = -1;
static struct ioloop *ioloop_nested = NULL;
static unsigned ioloop_nested_first = 0;
static unsigned ioloop_nested_last = 0;
static unsigned ioloop_nested_depth = 0;

static void main_deinit(void);

/*
 * Test settings
 */

static void test_init_defaults(void)
{
	i_zero(&tset);
	tset.max_pending = 200;
	tset.server_payload_handling = PAYLOAD_HANDLING_FORWARD;
	tset.parallel_clients = 1;
}

/*
 * Test files
 */
static const char unsafe_characters[] = "\"<>#%{}|\\^~[]` ;/?:@=&";

static ARRAY_TYPE(const_string) files;
static pool_t files_pool;

static void test_files_read_dir(const char *path)
{
	DIR *dirp;

	/* open the directory */
	if ((dirp = opendir(path)) == NULL) {
		if (errno == ENOENT || errno == EACCES)
			return;
		i_fatal("test files: "
			"failed to open directory %s: %m", path);
	}

	/* read entries */
	for (;;) {
		const char *file;
		struct dirent *dp;
		struct stat st;

		errno = 0;
		if ((dp = readdir(dirp)) == NULL)
			break;
		if (*dp->d_name == '.' ||
		    dp->d_name[strcspn(dp->d_name, unsafe_characters)] != '\0')
			continue;

		file = t_abspath_to(dp->d_name, path);
		if (stat(file, &st) == 0) {
			if (S_ISREG(st.st_mode)) {
				file += 2; /* skip "./" */
				file = p_strdup(files_pool, file);
				array_push_back(&files, &file);
			} else if (S_ISDIR(st.st_mode)) {
				test_files_read_dir(file);
			}
		}
	}

	if (errno != 0)
		i_fatal("test files: "
			"failed to read directory %s: %m", path);

	/* Close the directory */
	if (closedir(dirp) < 0)
		i_error("test files: "
			"failed to close directory %s: %m", path);
}

static void test_files_init(void)
{
	/* initialize file array */
	files_pool = pool_alloconly_create(
		MEMPOOL_GROWING"http_server_request", 4096);
	p_array_init(&files, files_pool, 512);

	/* obtain all filenames */
	test_files_read_dir(".");
}

static void test_files_deinit(void)
{
	pool_unref(&files_pool);
}

static struct istream *
test_file_open(const char *path, unsigned int *status_r, const char **reason_r)
	       ATTR_NULL(2, 3)
{
	int fd;

	if (status_r != NULL)
		*status_r = 200;
	if (reason_r != NULL)
		*reason_r = "OK";

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (debug)
			i_debug("test files: open(%s) failed: %m", path);

		switch (errno) {
		case EFAULT:
		case ENOENT:
			if (status_r != NULL)
				*status_r = 404;
			if (reason_r != NULL)
				*reason_r = "Not Found";
			break;
		case EISDIR:
		case EACCES:
			if (status_r != NULL)
				*status_r = 403;
			if (reason_r != NULL)
				*reason_r = "Forbidden";
			break;
		default:
			if (status_r != NULL)
				*status_r = 500;
			if (reason_r != NULL)
				*reason_r = "Internal Server Error";
		}
		return NULL;
	}

	return i_stream_create_fd_autoclose(&fd, 40960);
}

/*
 * Test server
 */

struct client {
	pool_t pool;
	struct client *prev, *next;

	struct http_server_connection *http_conn;
};

struct client_request {
	struct client *client;
	struct http_server_request *server_req;

	const char *path;

	struct istream *data;
	struct istream *payload_input;
	struct ostream *payload_output;
	struct io *io;

	bool all_sent:1;
};

static const struct http_server_callbacks http_callbacks;
static struct http_server *http_server;

static struct io *io_listen;
static struct client *clients;

/* location: /succes */

static void client_handle_success_request(struct client_request *creq)
{
	struct http_server_request *req = creq->server_req;
	const struct http_request *hreq = http_server_request_get(req);
	struct http_server_response *resp;

	if (strcmp(hreq->method, "GET") != 0) {
		http_server_request_fail(req,
			405, "Method Not Allowed");
		return;
	}

	resp = http_server_response_create(req, 200, "OK");
	http_server_response_submit(resp);
}

/* location: /download/... */

static void
client_handle_download_request(struct client_request *creq,
			       const char *path)
{
	struct http_server_request *req = creq->server_req;
	const struct http_request *hreq = http_server_request_get(req);
	struct http_server_response *resp;
	const char *fpath, *reason;
	struct istream *fstream;
	struct ostream *output;
	unsigned int status;
	int ret;

	if (strcmp(hreq->method, "GET") != 0) {
		http_server_request_fail(req,
			405, "Method Not Allowed");
		return;
	}

	fpath = t_strconcat(".", path, NULL);

	if (debug) {
		i_debug("test server: download: "
			"sending payload for %s", fpath);
	}

	fstream = test_file_open(fpath, &status, &reason);
	if (fstream == NULL) {
		http_server_request_fail(req, status, reason);
		return;
	}

	resp = http_server_response_create(req, 200, "OK");
	http_server_response_add_header(resp, "Content-Type", "text/plain");

	if (tset.server_blocking) {
		output = http_server_response_get_payload_output(
			resp, IO_BLOCK_SIZE, TRUE);

		switch (o_stream_send_istream(output, fstream)) {
		case OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT:
		case OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT:
			i_unreached();
		case OSTREAM_SEND_ISTREAM_RESULT_FINISHED:
			/* finish it */
			ret = o_stream_finish(output);
			i_assert(ret != 0);
			if (ret > 0)
				break;
			/* fall through */
		case OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT:
			i_assert(output->stream_errno != 0);
			i_fatal("test server: download: "
				"write(%s) failed: %s",
				o_stream_get_name(output),
				o_stream_get_error(output));
		case OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT:
			i_assert(fstream->stream_errno != 0);
			i_fatal("test server: download: "
				"read(%s) failed: %s",
				i_stream_get_name(fstream),
				i_stream_get_error(fstream));
		}

		if (debug) {
			i_debug("test server: download: "
				"finished sending blocking payload for %s"
				"(%"PRIuUOFF_T":%"PRIuUOFF_T")",
				fpath, fstream->v_offset, output->offset);
		}

		o_stream_destroy(&output);
	} else {
		http_server_response_set_payload(resp, fstream);
		http_server_response_submit(resp);
	}
	i_stream_unref(&fstream);
}

/* location: /echo */

static int client_request_echo_send_more(struct client_request *creq)
{
	struct ostream *output = creq->payload_output;
	enum ostream_send_istream_result res;
	uoff_t offset;
	int ret;

	if ((ret = o_stream_flush(output)) <= 0) {
		if (ret < 0) {
			i_fatal("test server: echo: "
				"write(%s) failed for %s (flush): %s",
				o_stream_get_name(output), creq->path,
				o_stream_get_error(output));
		}
		return ret;
	}

	if (creq->all_sent) {
		if (debug) {
			i_debug("test server: echo: "
				"flushed all payload for %s", creq->path);
		}
		i_stream_unref(&creq->data);
		o_stream_destroy(&creq->payload_output);
		return 1;
	}

	i_assert(output != NULL);
	i_assert(creq->data != NULL);

	offset = creq->data->v_offset;
	o_stream_set_max_buffer_size(output, IO_BLOCK_SIZE);
	res = o_stream_send_istream(output, creq->data);
	o_stream_set_max_buffer_size(output, SIZE_MAX);

	i_assert(creq->data->v_offset >= offset);
	if (debug) {
		i_debug("test server: echo: sent data for %s "
			"(sent %"PRIuUOFF_T", buffered %zu)",
			creq->path, (uoff_t)(creq->data->v_offset - offset),
			o_stream_get_buffer_used_size(output));
	}

	switch (res) {
	case OSTREAM_SEND_ISTREAM_RESULT_FINISHED:
		/* finish it */
		creq->all_sent = TRUE;
		if ((ret = o_stream_finish(output)) < 0) {
			i_fatal("test server: echo: "
				"write(%s) failed for %s (finish): %s",
				o_stream_get_name(output), creq->path,
				o_stream_get_error(output));
		}
		if (debug) {
			i_debug("test server: echo: "
				"finished sending payload for %s", creq->path);
		}
		if (ret == 0)
			return 0;
		if (debug) {
			i_debug("test server: echo: "
				"flushed all payload for %s", creq->path);
		}
		i_stream_unref(&creq->data);
		o_stream_destroy(&creq->payload_output);
		return 1;
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT:
		i_unreached();
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT:
		if (debug) {
			i_debug("test server echo: "
				"partially sent payload for %s", creq->path);
		}
		return 1;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT:
		i_fatal("test server: echo: "
			"read(%s) failed for %s: %s",
			i_stream_get_name(creq->data), creq->path,
			i_stream_get_error(creq->data));
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT:
		i_fatal("test server: echo: "
			"write(%s) failed for %s: %s",
			o_stream_get_name(output), creq->path,
			o_stream_get_error(output));
	}
	i_unreached();
}

static void
client_request_echo_ostream_nonblocking(struct client_request *creq,
					struct http_server_response *resp,
					struct istream *data)
{
	creq->data = data;
	i_stream_ref(data);

	creq->payload_output = http_server_response_get_payload_output(
		resp, IO_BLOCK_SIZE, FALSE);
	if (tset.server_cork)
		o_stream_cork(creq->payload_output);
	o_stream_set_flush_callback(creq->payload_output,
				    client_request_echo_send_more, creq);
	o_stream_set_flush_pending(creq->payload_output, TRUE);
}

static void
client_request_echo_blocking(struct client_request *creq,
			     struct http_server_response *resp,
			     struct istream *input)
{
	const unsigned char *data;
	size_t size;
	int ret;

	while ((ret = i_stream_read_more(input, &data, &size)) > 0) {
		ret = http_server_response_send_payload(&resp, data, size);
		i_assert(ret <= 0);
		if (ret < 0)
			break;
		i_stream_skip(input, size);
	}
	i_assert(ret < 0);
	if (input->stream_errno != 0) {
		i_fatal("test server: echo: "
			"read(%s) failed for %s: %s",
			i_stream_get_name(input), creq->path,
			i_stream_get_error(input));
	} else if (i_stream_have_bytes_left(input)) {
		i_fatal("test server: echo: "
			"failed to send all blocking payload for %s",
			creq->path);
	}

	/* finish it */
	if (http_server_response_finish_payload(&resp) < 0) {
		i_fatal("test server: echo: "
			"failed to finish blocking payload for %s", creq->path);
	}

	if (debug) {
		i_debug("test server: echo: "
			"sent all payload for %s", creq->path);
	}
}

static void
client_request_echo_ostream_blocking(struct client_request *creq,
				     struct http_server_response *resp,
				     struct istream *input)
{
	struct ostream *payload_output;
	int ret;

	payload_output = http_server_response_get_payload_output(
		resp, IO_BLOCK_SIZE, TRUE);

	if (tset.server_cork)
		o_stream_cork(payload_output);

	switch (o_stream_send_istream(payload_output, input)) {
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT:
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT:
		i_unreached();
	case OSTREAM_SEND_ISTREAM_RESULT_FINISHED:
		/* finish it */
		ret = o_stream_finish(payload_output);
		i_assert(ret != 0);
		if (ret > 0)
			break;
		/* fall through */
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT:
		i_assert(payload_output->stream_errno != 0);
		i_fatal("test server: echo: "
			"write(%s) failed for %s: %s",
			o_stream_get_name(payload_output), creq->path,
			o_stream_get_error(payload_output));
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT:
		i_assert(input->stream_errno != 0);
		i_fatal("test server: echo: "
			"read(%s) failed for %s: %s",
			i_stream_get_name(input), creq->path,
			i_stream_get_error(input));
	}

	if (debug) {
		i_debug("test server: echo: "
			"sent all payload for %s", creq->path);
	}

	o_stream_destroy(&payload_output);
}

static void client_request_finish_payload_in(struct client_request *creq)
{
	struct http_server_response *resp;
	struct istream *payload_input;

	payload_input =
		iostream_temp_finish(&creq->payload_output, 4096);

	if (debug) {
		i_debug("test server: echo: "
			"finished receiving payload for %s", creq->path);
	}

	resp = http_server_response_create(creq->server_req, 200, "OK");
	http_server_response_add_header(resp, "Content-Type", "text/plain");

	if (tset.server_ostream) {
		client_request_echo_ostream_nonblocking(creq, resp,
							payload_input);
	} else {
		http_server_response_set_payload(resp, payload_input);
		http_server_response_submit(resp);
	}

	i_stream_unref(&payload_input);
}

static void client_request_read_echo(struct client_request *creq)
{
	enum ostream_send_istream_result res;

	o_stream_set_max_buffer_size(creq->payload_output, IO_BLOCK_SIZE);
	res = o_stream_send_istream(creq->payload_output, creq->payload_input);
	o_stream_set_max_buffer_size(creq->payload_output, SIZE_MAX);

	switch (res) {
	case OSTREAM_SEND_ISTREAM_RESULT_FINISHED:
		break;
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT:
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT:
		return;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT:
		i_fatal("test server: echo: "
			"Failed to read all echo payload [%s]",
			creq->path);
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT:
		i_fatal("test server: echo: "
			"Failed to write all echo payload [%s]",
			creq->path);
	}

	client_request_finish_payload_in(creq);
	i_stream_unref(&creq->payload_input);
}

static void client_request_read_echo_more(struct client_request *creq)
{
	client_request_read_echo(creq);

	if (creq->payload_input != NULL)
		return;

	io_remove(&creq->io);

	if (debug) {
		i_debug("test server: echo: "
			"finished receiving payload for %s",
			creq->path);
	}
}

static void
client_handle_echo_request(struct client_request *creq,
			   const char *path)
{
	struct http_server_request *req = creq->server_req;
	const struct http_request *hreq = http_server_request_get(req);
	struct http_server_response *resp;
	struct ostream *payload_output;
	uoff_t size;

	creq->path = p_strdup(http_server_request_get_pool(req), path);

	if (strcmp(hreq->method, "PUT") != 0) {
		http_server_request_fail(req,
			405, "Method Not Allowed");
		return;
	}

	size = 0;
	if (http_request_get_payload_size(hreq, &size) > 0 && size == 0) {
		if (debug) {
			i_debug("test server: echo: "
				"empty payload for %s", creq->path);
		}

		resp = http_server_response_create(creq->server_req, 200, "OK");
		http_server_response_add_header(
			resp, "Content-Type", "text/plain");
		http_server_response_submit(resp);
		return;
	}

	payload_output = iostream_temp_create("/tmp/test-http-server", 0);

	if (tset.server_blocking) {
		struct istream *payload_input;

		payload_input =
			http_server_request_get_payload_input(req, TRUE);

		if (tset.read_server_partial > 0) {
			struct istream *partial =
				i_stream_create_limit(payload_input,
						      tset.read_server_partial);
			i_stream_unref(&payload_input);
			payload_input = partial;
		}

		if (o_stream_send_istream(payload_output, payload_input) !=
			OSTREAM_SEND_ISTREAM_RESULT_FINISHED) {
			i_fatal("test server: echo: "
				"failed to receive blocking echo payload");
		}
		i_stream_unref(&payload_input);

		payload_input = iostream_temp_finish(&payload_output, 4096);

		if (debug) {
			i_debug("test server: echo: "
				"finished receiving blocking payload for %s",
				path);
		}

		resp = http_server_response_create(req, 200, "OK");
		http_server_response_add_header(resp,
			"Content-Type", "text/plain");

		if (tset.server_ostream) {
			client_request_echo_ostream_blocking(creq, resp,
							     payload_input);
		} else {
			client_request_echo_blocking(creq, resp, payload_input);
		}
		i_stream_unref(&payload_input);
	} else {
		creq->payload_output = payload_output;

		switch (tset.server_payload_handling) {
		case PAYLOAD_HANDLING_LOW_LEVEL:
			creq->payload_input =
				http_server_request_get_payload_input(req, FALSE);

			if (tset.read_server_partial > 0) {
				struct istream *partial =
					i_stream_create_limit(creq->payload_input,
							      tset.read_server_partial);
				i_stream_unref(&creq->payload_input);
				creq->payload_input = partial;
			}

			creq->io = io_add_istream(creq->payload_input,
					 client_request_read_echo_more, creq);
			client_request_read_echo_more(creq);
			break;
		case PAYLOAD_HANDLING_FORWARD:
			http_server_request_forward_payload(req,
				payload_output, SIZE_MAX,
				client_request_finish_payload_in, creq);
			break;
		case PAYLOAD_HANDLING_HANDLER:
			creq->payload_input =
				http_server_request_get_payload_input(req, FALSE);
			http_server_request_handle_payload(req,
				client_request_read_echo, creq);
			break;
		}
	}
}

/* request */

static void http_server_request_destroyed(struct client_request *creq);

static struct client_request *
client_request_init(struct client *client,
		    struct http_server_request *req)
{
	struct client_request *creq;
	pool_t pool = http_server_request_get_pool(req);

	http_server_request_ref(req);

	creq = p_new(pool, struct client_request, 1);
	creq->client = client;
	creq->server_req = req;

	http_server_request_set_destroy_callback(req,
		http_server_request_destroyed, creq);

	return creq;
}

static void client_request_deinit(struct client_request **_creq)
{
	struct client_request *creq = *_creq;
	struct http_server_request *req = creq->server_req;

	*_creq = NULL;

	i_stream_unref(&creq->data);
	i_stream_unref(&creq->payload_input);
	io_remove(&creq->io);

	http_server_request_unref(&req);
}

static void http_server_request_destroyed(struct client_request *creq)
{
	client_request_deinit(&creq);
}

static void
client_handle_request(void *context,
		      struct http_server_request *req)
{
	const struct http_request *hreq = http_server_request_get(req);
	const char *path = hreq->target.url->path, *p;
	struct client *client = (struct client *)context;
	struct client_request *creq;

	if (debug) {
		i_debug("test server: request method=`%s' path=`%s'",
			hreq->method, path);
	}

	creq = client_request_init(client, req);

	if (strcmp(path, "/success") == 0) {
		client_handle_success_request(creq);
		return;
	}

	if ((p = strchr(path+1, '/')) == NULL) {
		http_server_request_fail(req, 404, "Not found");
		return;
	}
	if (strncmp(path, "/download", p-path) == 0) {
		client_handle_download_request(creq, p);
		return;
	}
	if (strncmp(path, "/echo", p-path) == 0) {
		client_handle_echo_request(creq, p);
		return;
	}

	http_server_request_fail(req, 404, "Not found");
	return;
}

/* client connection */

static void client_connection_destroy(void *context, const char *reason);

static const struct http_server_callbacks http_callbacks = {
	.connection_destroy = client_connection_destroy,
	.handle_request = client_handle_request,
};

static void client_init(int fd)
{
	struct client *client;
	pool_t pool;

	net_set_nonblock(fd, TRUE);

	pool = pool_alloconly_create("client", 512);
	client = p_new(pool, struct client, 1);
	client->pool = pool;

	client->http_conn = http_server_connection_create(
		http_server, fd, fd, tset.ssl, &http_callbacks, client);
	DLLIST_PREPEND(&clients, client);
}

static void client_deinit(struct client **_client)
{
	struct client *client = *_client;

	*_client = NULL;

	DLLIST_REMOVE(&clients, client);

	if (client->http_conn != NULL) {
		http_server_connection_close(&client->http_conn,
					     "deinit");
	}
	pool_unref(&client->pool);
}

static void
client_connection_destroy(void *context, const char *reason ATTR_UNUSED)
{
	struct client *client = context;

	client->http_conn = NULL;
	client_deinit(&client);
}

static void client_accept(void *context ATTR_UNUSED)
{
	int fd;

	for (;;) {
		/* accept new client */
		if ((fd = net_accept(fd_listen, NULL, NULL)) < 0) {
			if (errno == EAGAIN)
				break;
			if (errno == ECONNABORTED)
				continue;
			i_fatal("test server: accept() failed: %m");
		}

		client_init(fd);
	}
}

/* */

static void test_server_init(const struct http_server_settings *server_set)
{
	/* open server socket */
	io_listen = io_add(fd_listen, IO_READ, client_accept, NULL);

	http_server = http_server_init(server_set);
}

static void test_server_deinit(void)
{
	/* close server socket */
	io_remove(&io_listen);

	/* deinitialize */
	http_server_deinit(&http_server);
}

/*
 * Test client
 */

struct test_client_request {
	int refcount;

	struct test_client_request *prev, *next;
	struct http_client *client;
	struct http_client_request *hreq;

	struct io *io;
	struct istream *payload;
	struct istream *file_in, *file_out;
	unsigned int files_idx;
};

static struct http_client **http_clients;
static struct test_client_request *client_requests;
static unsigned int client_files_first, client_files_last;
struct timeout *to_client_progress = NULL;

static struct test_client_request *
test_client_request_new(struct http_client *client)
{
	struct test_client_request *tcreq;

	tcreq = i_new(struct test_client_request, 1);
	tcreq->refcount = 1;
	tcreq->client = client;
	DLLIST_PREPEND(&client_requests, tcreq);

	return tcreq;
}

static void test_client_request_ref(struct test_client_request *tcreq)
{
	tcreq->refcount++;
}

static void test_client_request_unref(struct test_client_request **_tcreq)
{
	struct test_client_request *tcreq = *_tcreq;

	*_tcreq = NULL;

	i_assert(tcreq->refcount > 0);
	if (--tcreq->refcount > 0)
		return;

	io_remove(&tcreq->io);
	i_stream_unref(&tcreq->payload);
	i_stream_unref(&tcreq->file_in);
	i_stream_unref(&tcreq->file_out);

	DLLIST_REMOVE(&client_requests, tcreq);
	i_free(tcreq);
}

static void test_client_request_destroy(struct test_client_request *tcreq)
{
	test_client_request_unref(&tcreq);
}

static void test_client_switch_ioloop(void)
{
	struct test_client_request *tcreq;

	if (to_continue != NULL)
		to_continue = io_loop_move_timeout(&to_continue);
	if (to_client_progress != NULL)
		to_client_progress = io_loop_move_timeout(&to_client_progress);

	for (tcreq = client_requests; tcreq != NULL;
		tcreq = tcreq->next) {
		if (tcreq->io != NULL)
			tcreq->io = io_loop_move_io(&tcreq->io);
		if (tcreq->payload != NULL)
			i_stream_switch_ioloop(tcreq->payload);
	}
}

static void test_client_progress_timeout(void *context ATTR_UNUSED)
{
	/* Terminate test due to lack of progress */
	failure = "Test is hanging";
	timeout_remove(&to_client_progress);
	io_loop_stop(current_ioloop);
}

static void
test_client_create_clients(const struct http_client_settings *client_set)
{
	struct http_client_context *http_context = NULL;
	unsigned int i;

	if (!small_socket_buffers) {
		to_client_progress = timeout_add(
			CLIENT_PROGRESS_TIMEOUT*1000,
			test_client_progress_timeout, NULL);
	}

	if (!tset.parallel_clients_global)
		http_context = http_client_context_create(client_set);

	if (tset.parallel_clients < 1)
		tset.parallel_clients = 1;
	http_clients = i_new(struct http_client *, tset.parallel_clients);
	for (i = 0; i < tset.parallel_clients; i++) {
		http_clients[i] = (tset.parallel_clients_global ?
				   http_client_init(client_set) :
				   http_client_init_shared(http_context, NULL));
	}

	if (!tset.parallel_clients_global)
		http_client_context_unref(&http_context);
}

/* download */

static void test_client_download_continue(void);

static void test_client_download_finished(struct test_client_request *tcreq)
{
	const char **paths;
	unsigned int files_idx = tcreq->files_idx;
	unsigned int count;

	paths = array_get_modifiable(&files, &count);
	i_assert(files_idx < count);
	i_assert(client_files_first < count);
	i_assert(paths[files_idx] != NULL);

	paths[files_idx] = NULL;
	test_client_download_continue();
}

static void
test_client_download_payload_input(struct test_client_request *tcreq)
{
	struct istream *payload = tcreq->payload;
	const unsigned char *pdata, *fdata;
	size_t psize, fsize, pleft;
	off_t ret;

	if (to_client_progress != NULL)
		timeout_reset(to_client_progress);

	/* read payload */
	while ((ret = i_stream_read_more(payload, &pdata, &psize)) > 0) {
		if (debug) {
			i_debug("test client: download: "
				"got data for [%u] (size=%d)",
				tcreq->files_idx, (int)psize);
		}
		/* compare with file on disk */
		pleft = psize;
		while ((ret = i_stream_read_more(tcreq->file_in,
						 &fdata, &fsize)) > 0 &&
		       pleft > 0) {
			fsize = (fsize > pleft ? pleft : fsize);
			if (memcmp(pdata, fdata, fsize) != 0) {
				i_fatal("test client: download: "
					"received data does not match file "
					"(%"PRIuUOFF_T":%"PRIuUOFF_T")",
					payload->v_offset,
					tcreq->file_in->v_offset);
			}
			i_stream_skip(tcreq->file_in, fsize);
			pleft -= fsize;
			pdata += fsize;
		}
		if (ret < 0 && tcreq->file_in->stream_errno != 0) {
			i_fatal("test client: download: "
				"failed to read file: %s",
				i_stream_get_error(tcreq->file_in));
		}
		i_stream_skip(payload, psize);
	}

	if (ret == 0) {
		if (debug) {
			i_debug("test client: download: "
				"need more data for [%u]",
				tcreq->files_idx);
		}
		/* we will be called again for this request */
	} else {
		(void)i_stream_read(tcreq->file_in);
		if (payload->stream_errno != 0) {
			i_fatal("test client: download: "
				"failed to read request payload: %s",
				i_stream_get_error(payload));
		} if (i_stream_have_bytes_left(tcreq->file_in)) {
			if (i_stream_read_more(tcreq->file_in,
					       &fdata, &fsize) <= 0)
				fsize = 0;
			i_fatal("test client: download: "
				"payload ended prematurely "
				"(at least %zu bytes left)", fsize);
		} else if (debug) {
			i_debug("test client: download: "
				"finished request for [%u]",
				tcreq->files_idx);
		}

		/* finished */
		tcreq->payload = NULL;
		test_client_download_finished(tcreq);

		/* dereference payload stream; finishes the request */
		i_stream_unref(&tcreq->file_in);
		io_remove(&tcreq->io); /* holds a reference too */
		i_stream_unref(&payload);
	}
}

static void
test_client_download_response(const struct http_response *resp,
			      struct test_client_request *tcreq)
{
	const char **paths;
	const char *path;
	unsigned int count, status;
	struct istream *fstream;
	const char *reason;

	if (debug) {
		i_debug("test client: download: got response for [%u]",
			tcreq->files_idx);
	}

	if (to_client_progress != NULL)
		timeout_reset(to_client_progress);

	paths = array_get_modifiable(&files, &count);
	i_assert(tcreq->files_idx < count);
	i_assert(client_files_first < count);
	path = paths[tcreq->files_idx];
	i_assert(path != NULL);

	if (debug) {
		i_debug("test client: download: path for [%u]: %s",
			tcreq->files_idx, path);
	}

	fstream = test_file_open(path, &status, &reason);
	i_assert(fstream != NULL);

	if (status != resp->status) {
		i_fatal("test client: download: "
			"got wrong response for %s: %u %s "
			"(expected: %u %s)", path,
			resp->status, resp->reason, status, reason);
	}

	if (resp->status / 100 != 2) {
		if (debug) {
			i_debug("test client: download: "
				"HTTP request for %s failed: %u %s",
				path, resp->status, resp->reason);
		}
		i_stream_unref(&fstream);
		test_client_download_finished(tcreq);
		return;
	}

	if (resp->payload == NULL) {
		if (debug) {
			i_debug("test client: download: "
				"no payload for %s [%u]",
				path, tcreq->files_idx);
		}
		i_stream_unref(&fstream);
		test_client_download_finished(tcreq);
		return;
	}

	i_assert(fstream != NULL);
	if (tset.read_client_partial == 0) {
		i_stream_ref(resp->payload);
		tcreq->payload = resp->payload;
		tcreq->file_in = fstream;
	} else {
		struct istream *payload = resp->payload;
		tcreq->payload = i_stream_create_limit(
			payload, tset.read_client_partial);
		tcreq->file_in = i_stream_create_limit(
			fstream, tset.read_client_partial);
		i_stream_unref(&fstream);
	}

	tcreq->io = io_add_istream(tcreq->payload,
		test_client_download_payload_input, tcreq);
	test_client_download_payload_input(tcreq);
}

static void test_client_download_continue(void)
{
	struct test_client_request *tcreq;
	struct http_client_request *hreq;
	const char *const *paths;
	unsigned int count;

	paths = array_get(&files, &count);
	i_assert(client_files_first <= count);
	i_assert(client_files_last <= count);

	i_assert(client_files_first <= client_files_last);
	for (; client_files_first < client_files_last &&
		paths[client_files_first] == NULL; client_files_first++)

	if (debug) {
		i_debug("test client: download: received until [%u]",
			client_files_first-1);
	}

	if (client_files_first >= count) {
		io_loop_stop(current_ioloop);
		return;
	}

	for (; (client_files_last < count &&
	        (client_files_last - client_files_first) < tset.max_pending);
	     client_files_last++) {
		struct http_client *http_client =
			http_clients[client_files_last % tset.parallel_clients];
		const char *path = paths[client_files_last];

		tcreq = test_client_request_new(http_client);
		tcreq->files_idx = client_files_last;

		if (debug) {
			i_debug("test client: download: retrieving %s [%u]",
				path, tcreq->files_idx);
		}
		hreq = tcreq->hreq = http_client_request(
			http_client, "GET", net_ip2addr(&bind_ip),
			t_strconcat("/download/", path, NULL),
			test_client_download_response, tcreq);
		http_client_request_set_port(hreq, bind_port);
		http_client_request_set_ssl(hreq, tset.ssl);
		http_client_request_set_destroy_callback(
			hreq, test_client_request_destroy, tcreq);
		http_client_request_submit(hreq);
	}
}

static void test_client_download(const struct http_client_settings *client_set)
{
	/* create client(s) */
	test_client_create_clients(client_set);

	/* start querying server */
	client_files_first = client_files_last = 0;
	test_client_download_continue();
}

/* echo */

static void test_client_echo_continue(void *context);

static void test_client_echo_finished(struct test_client_request *tcreq)
{
	unsigned int files_idx = tcreq->files_idx;
	const char **paths;
	unsigned int count;

	paths = array_get_modifiable(&files, &count);
	i_assert(files_idx < count);
	i_assert(client_files_first < count);
	i_assert(paths[files_idx] != NULL);

	if (tcreq->file_out != NULL)
		return;
	if (tcreq->file_in != NULL)
		return;

	if (debug) {
		i_debug("test client: echo: finished [%u]: %s",
			files_idx, paths[files_idx]);
	}

	paths[files_idx] = NULL;
	files_finished = TRUE;
	if (!running_continue && to_continue == NULL) {
		to_continue = timeout_add_short(0,
			test_client_echo_continue, NULL);
	}
}

static void test_client_echo_payload_input(struct test_client_request *tcreq)
{
	struct istream *payload = tcreq->payload;
	const unsigned char *pdata, *fdata;
	size_t psize, fsize, pleft;
	off_t ret;

	if (to_client_progress != NULL)
		timeout_reset(to_client_progress);

	/* read payload */
	while ((ret = i_stream_read_more(payload, &pdata, &psize)) > 0) {
		if (debug) {
			i_debug("test client: echo: "
				"got data for [%u] (size=%d)",
				tcreq->files_idx, (int)psize);
		}
		/* compare with file on disk */
		pleft = psize;
		while ((ret = i_stream_read_more(tcreq->file_in,
						 &fdata, &fsize)) > 0 &&
		       pleft > 0) {
			fsize = (fsize > pleft ? pleft : fsize);
			if (memcmp(pdata, fdata, fsize) != 0) {
				i_fatal("test client: echo: "
					"received data does not match file "
					"(%"PRIuUOFF_T":%"PRIuUOFF_T")",
					payload->v_offset,
					tcreq->file_in->v_offset);
			}
			i_stream_skip(tcreq->file_in, fsize);
			pleft -= fsize;
			pdata += fsize;
		}
		if (ret < 0 && tcreq->file_in->stream_errno != 0) {
			i_fatal("test client: echo: "
				"failed to read file: %s",
				i_stream_get_error(tcreq->file_in));
		}
		i_stream_skip(payload, psize);
	}

	if (ret == 0) {
		if (debug) {
			i_debug("test client: echo: "
				"need more data for [%u]",
				tcreq->files_idx);
		}
		/* we will be called again for this request */
	} else {
		(void)i_stream_read(tcreq->file_in);
		if (payload->stream_errno != 0) {
			i_fatal("test client: echo: "
				"failed to read request payload: %s",
				i_stream_get_error(payload));
		} if (i_stream_have_bytes_left(tcreq->file_in)) {
			if (i_stream_read_more(tcreq->file_in,
					       &fdata, &fsize) <= 0)
				fsize = 0;
			i_fatal("test client: echo: "
				"payload ended prematurely "
				"(at least %zu bytes left)", fsize);
		} else if (debug) {
			i_debug("test client: echo: "
				"finished request for [%u]",
				tcreq->files_idx);
		}

		/* finished */
		tcreq->payload = NULL;
		i_stream_unref(&tcreq->file_in);
		test_client_echo_finished(tcreq);

		/* dereference payload stream; finishes the request */
		io_remove(&tcreq->io); /* holds a reference too */
		i_stream_unref(&payload);
	}
}

static void
test_client_echo_response(const struct http_response *resp,
			  struct test_client_request *tcreq)
{
	const char **paths;
	const char *path;
	unsigned int count, status;
	struct istream *fstream;

	if (debug) {
		i_debug("test client: echo: got response for [%u]",
			tcreq->files_idx);
	}

	if (to_client_progress != NULL)
		timeout_reset(to_client_progress);

	paths = array_get_modifiable(&files, &count);
	i_assert(tcreq->files_idx < count);
	i_assert(client_files_first < count);
	path = paths[tcreq->files_idx];
	i_assert(path != NULL);

	if (debug) {
		i_debug("test client: echo: path for [%u]: %s",
			tcreq->files_idx, path);
	}

	if (resp->status / 100 != 2) {
		i_fatal("test client: echo: "
			"HTTP request for %s failed: %u %s",
			path, resp->status, resp->reason);
	}

	fstream = test_file_open(path, &status, NULL);
	if (fstream == NULL) {
		i_fatal("test client: echo: failed to open %s", path);
	}

	if (tset.unknown_size) {
		struct istream *ustream;

		ustream = i_stream_create_crlf(fstream);
		i_stream_unref(&fstream);
		fstream = ustream;
	}

	if (tset.read_server_partial > 0) {
		struct istream *partial =
			i_stream_create_limit(fstream, tset.read_server_partial);
		i_stream_unref(&fstream);
		fstream = partial;
	}

	if (resp->payload == NULL) {
		// FIXME: check file is empty
		if (debug) {
			i_debug("test client: echo: "
				"no payload for %s [%u]",
				path, tcreq->files_idx);
		}
		i_stream_unref(&fstream);
		test_client_echo_finished(tcreq);
		return;
	}

	i_assert(fstream != NULL);
	tcreq->file_in = fstream;

	i_stream_ref(resp->payload);
	tcreq->payload = resp->payload;
	tcreq->io = io_add_istream(resp->payload,
		test_client_echo_payload_input, tcreq);
	test_client_echo_payload_input(tcreq);
}

static void
test_client_echo_nonblocking(struct test_client_request *tcreq ATTR_UNUSED,
			     struct http_client_request *hreq,
			     struct istream *fstream)
{
	http_client_request_set_payload(hreq, fstream,
					tset.request_100_continue);
	http_client_request_submit(hreq);
}

static void
test_client_echo_blocking(struct test_client_request *tcreq,
			  struct http_client_request *hreq,
			  struct istream *fstream)
{
	const unsigned char *data;
	size_t size;
	int ret;

	test_client_request_ref(tcreq);
	tcreq->file_out = fstream;

	while ((ret = i_stream_read_more(fstream, &data, &size)) > 0) {
		ret = http_client_request_send_payload(&hreq, data, size);
		i_assert(ret <= 0);
		if (ret < 0)
			break;
		i_stream_skip(fstream, size);
	}
	i_assert(ret < 0);
	if (fstream->stream_errno != 0) {
		i_fatal("test client: echo: "
			"read(%s) failed: %s [%u]",
			i_stream_get_name(fstream),
			i_stream_get_error(fstream),
			tcreq->files_idx);
	} else if (i_stream_have_bytes_left(fstream)) {
		i_fatal("test client: echo: "
			"failed to send all blocking payload [%u]",
			tcreq->files_idx);
	}

	/* finish it */
	if (http_client_request_finish_payload(&hreq) < 0) {
		i_fatal("test client: echo: "
			"failed to finish blocking payload [%u]",
			tcreq->files_idx);
	}
	http_client_wait(tcreq->client);

	if (debug) {
		i_debug("test client: echo: "
			"sent all payload [%u]",
			tcreq->files_idx);
	}

	tcreq->file_out = NULL;
	test_client_echo_finished(tcreq);
	test_client_request_unref(&tcreq);
}

static void test_client_echo_continue(void *context ATTR_UNUSED)
{
	struct test_client_request *tcreq;
	struct http_client_request *hreq;
	const char **paths;
	unsigned int count, first_submitted;
	bool prev_files_finished = files_finished;

	running_continue = TRUE;
	files_finished = FALSE;
	timeout_remove(&to_continue);

	paths = array_get_modifiable(&files, &count);

	i_assert(client_files_first <= count);
	i_assert(client_files_last <= count);

	i_assert(client_files_first <= client_files_last);
	for (; client_files_first < client_files_last &&
		paths[client_files_first] == NULL; client_files_first++);

	if (debug) {
		i_debug("test client: echo: received until [%u/%u]",
			client_files_first-1, count);
	}

	if (debug && client_files_first < count) {
		const char *path = paths[client_files_first];
		i_debug("test client: echo: next blocking: %s [%d]",
			(path == NULL ? "none" : path), client_files_first);
	}

	if (client_files_first >= count || failure != NULL) {
		running_continue = FALSE;
		files_finished = prev_files_finished;
		io_loop_stop(current_ioloop);
		return;
	}

	first_submitted = client_files_last;
	for (; (client_files_last < count &&
	        (client_files_last - client_files_first) < tset.max_pending);
	     client_files_last++) {
		struct http_client *http_client =
			http_clients[client_files_last % tset.parallel_clients];
		struct istream *fstream;
		const char *path = paths[client_files_last];

		fstream = test_file_open(path, NULL, NULL);
		if (fstream == NULL) {
			paths[client_files_last] = NULL;
			if (debug) {
				i_debug("test client: echo: "
					"skipping %s [%u]",
					path, client_files_last);
			}
			continue;
		}

		if (debug) {
			i_debug("test client: echo: retrieving %s [%u]",
				path, client_files_last);
		}

		if (tset.unknown_size) {
			struct istream *ustream;

			ustream = i_stream_create_crlf(fstream);
			i_stream_unref(&fstream);
			fstream = ustream;
		}

		tcreq = test_client_request_new(http_client);
		tcreq->files_idx = client_files_last;

		hreq = tcreq->hreq = http_client_request(http_client,
			"PUT", net_ip2addr(&bind_ip),
			t_strconcat("/echo/", path, NULL),
			test_client_echo_response, tcreq);
		http_client_request_set_port(hreq, bind_port);
		http_client_request_set_ssl(hreq, tset.ssl);
		http_client_request_set_destroy_callback(hreq,
			test_client_request_destroy, tcreq);

		if (!tset.client_blocking)
			test_client_echo_nonblocking(tcreq, hreq, fstream);
		else
			test_client_echo_blocking(tcreq, hreq, fstream);
		i_stream_unref(&fstream);

		if (tset.client_blocking && paths[client_files_last] != NULL) {
			running_continue = FALSE;
			files_finished = prev_files_finished;
			return;
		}
	}

	if (files_finished && to_continue == NULL) {
		to_continue = timeout_add_short(
			0, test_client_echo_continue, NULL);
	}
	running_continue = FALSE;
	files_finished = prev_files_finished;

	/* run nested ioloop (if requested) if new requests cross a nesting
	   boundary */
	if (ioloop_nested != NULL) {
		unsigned int i;

		i_assert(ioloop_nested_first <= count);
		i_assert(ioloop_nested_last <= count);
		for (i = ioloop_nested_first; i < ioloop_nested_last; i++) {
			if (paths[i] != NULL) {
				if (debug) {
					i_debug("test client: "
						"not leaving ioloop [%u]", i);
				}
				break;
			}
		}

		if (i == ioloop_nested_last)
			io_loop_stop(ioloop_nested);
	} else if (tset.client_ioloop_nesting > 0 &&
		   ((client_files_last / tset.client_ioloop_nesting) !=
			(first_submitted / tset.client_ioloop_nesting))) {
		struct ioloop *prev_ioloop = current_ioloop;
		unsigned int i;

		ioloop_nested_first = first_submitted;
		ioloop_nested_last =
			first_submitted + tset.client_ioloop_nesting;
		if (ioloop_nested_last > client_files_last)
			ioloop_nested_last = client_files_last;

		if (debug) {
			i_debug("test client: "
				"echo: entering ioloop for %u...%u (depth=%u)",
				ioloop_nested_first, ioloop_nested_last,
				ioloop_nested_depth);
		}

		ioloop_nested_depth++;

		ioloop_nested = io_loop_create();
		for (i = 0; i < tset.parallel_clients; i++)
			http_client_switch_ioloop(http_clients[i]);
		test_client_switch_ioloop();

		io_loop_run(ioloop_nested);

		io_loop_set_current(prev_ioloop);
		for (i = 0; i < tset.parallel_clients; i++)
			http_client_switch_ioloop(http_clients[i]);
		test_client_switch_ioloop();
		io_loop_set_current(ioloop_nested);
		io_loop_destroy(&ioloop_nested);
		ioloop_nested = NULL;

		ioloop_nested_depth--;

		if (debug) {
			i_debug("test client: echo: leaving ioloop for %u...%u "
				"(depth=%u)", ioloop_nested_first,
				ioloop_nested_last, ioloop_nested_depth);
		}
		ioloop_nested_first = ioloop_nested_last = 0;

		if (client_files_first >= count || failure != NULL) {
			io_loop_stop(current_ioloop);
			return;
		}
	}
}

static void test_client_echo(const struct http_client_settings *client_set)
{
	/* create client */
	test_client_create_clients(client_set);

	/* start querying server */
	client_files_first = client_files_last = 0;

	i_assert(to_continue == NULL);
	to_continue = timeout_add_short(0, test_client_echo_continue, NULL);
}

/* cleanup */

static void test_client_deinit(void)
{
	unsigned int i;

	for (i = 0; i < tset.parallel_clients; i++)
		http_client_deinit(&http_clients[i]);
	i_free(http_clients);

	tset.parallel_clients = 1;

	timeout_remove(&to_continue);
	timeout_remove(&to_client_progress);
}

/*
 * Tests
 */

struct test_server_data {
	const struct http_server_settings *set;
};

static void test_open_server_fd(void)
{
	i_close_fd(&fd_listen);
	fd_listen = net_listen(&bind_ip, &bind_port, 128);
	if (fd_listen == -1) {
		i_fatal("listen(%s:%u) failed: %m",
			net_ip2addr(&bind_ip), bind_port);
	}
	net_set_nonblock(fd_listen, TRUE);
}

static int test_run_server(struct test_server_data *data)
{
	const struct http_server_settings *server_set = data->set;
	struct ioloop *ioloop;

	i_set_failure_prefix("SERVER: ");

	if (debug)
		i_debug("PID=%s", my_pid);

	ioloop_nested = NULL;
	ioloop_nested_depth = 0;
	ioloop = io_loop_create();
	test_server_init(server_set);
	io_loop_run(ioloop);
	test_server_deinit();
	io_loop_destroy(&ioloop);

	if (debug)
		i_debug("Terminated");

	i_close_fd(&fd_listen);
	test_files_deinit();
	main_deinit();
	return 0;
}

static void
test_run_client(
	const struct http_client_settings *client_set,
	void (*client_init)(const struct http_client_settings *client_set))
{
	struct ioloop *ioloop;

	i_set_failure_prefix("CLIENT: ");

	if (debug)
		i_debug("PID=%s", my_pid);

	ioloop_nested = NULL;
	ioloop_nested_depth = 0;
	ioloop = io_loop_create();
	client_init(client_set);
	io_loop_run(ioloop);
	test_client_deinit();
	io_loop_destroy(&ioloop);

	if (debug)
		i_debug("Terminated");
}

static void
test_run_client_server(
	const struct http_client_settings *client_set,
	const struct http_server_settings *server_set,
	void (*client_init)(const struct http_client_settings *client_set))
{
	struct test_server_data data;

	failure = NULL;

	test_files_init();

	i_zero(&data);
	data.set = server_set;

	/* Fork server */
	test_open_server_fd();
	test_subprocess_fork(test_run_server, &data, FALSE);
	i_close_fd(&fd_listen);

	/* Run client */
	test_run_client(client_set, client_init);

	i_unset_failure_prefix();
	test_subprocess_kill_all(SERVER_KILL_TIMEOUT_SECS);
	test_files_deinit();
}

static void
test_init_server_settings(struct http_server_settings *server_set_r)
{
	i_zero(server_set_r);
	server_set_r->request_limits.max_payload_size = UOFF_T_MAX;
	server_set_r->debug = debug;

	if (small_socket_buffers) {
		server_set_r->socket_send_buffer_size = 40960;
		server_set_r->socket_recv_buffer_size = 40960;
	}
}

static void
test_init_client_settings(struct http_client_settings *client_set_r)
{
	i_zero(client_set_r);
	client_set_r->max_redirects = 0;
	client_set_r->max_attempts = 1;
	client_set_r->max_idle_time_msecs =  5* 1000;
	client_set_r->debug = debug;

	if (small_socket_buffers) {
		client_set_r->socket_send_buffer_size = 40960;
		client_set_r->socket_recv_buffer_size = 40960;
		client_set_r->request_timeout_msecs = 20 * 60 * 1000;
		client_set_r->connect_timeout_msecs = 20 * 60 * 1000;
	}
}

static void
test_run_sequential(
	void (*client_init)(const struct http_client_settings *client_set))
{
	struct http_server_settings http_server_set;
	struct http_client_settings http_client_set;
	struct ssl_iostream_settings ssl_server_set, ssl_client_set;

	/* download files from blocking server */

	/* ssl settings */
	ssl_iostream_test_settings_server(&ssl_server_set);
	ssl_server_set.verbose = debug;
	ssl_iostream_test_settings_client(&ssl_client_set);
	ssl_client_set.verbose = debug;

	/* server settings */
	test_init_server_settings(&http_server_set);
	http_server_set.ssl = &ssl_server_set;
	http_server_set.max_pipelined_requests = 0;

	/* client settings */
	test_init_client_settings(&http_client_set);
	http_client_set.ssl = &ssl_client_set;
	http_client_set.max_parallel_connections = 1;
	http_client_set.max_pipelined_requests = 1;

	test_run_client_server(&http_client_set, &http_server_set, client_init);

	test_out_reason("sequential", (failure == NULL), failure);
}

static void
test_run_pipeline(
	void (*client_init)(const struct http_client_settings *client_set))
{
	struct http_server_settings http_server_set;
	struct http_client_settings http_client_set;
	struct ssl_iostream_settings ssl_server_set, ssl_client_set;

	/* download files from blocking server */

	/* ssl settings */
	ssl_iostream_test_settings_server(&ssl_server_set);
	ssl_server_set.verbose = debug;
	ssl_iostream_test_settings_client(&ssl_client_set);
	ssl_client_set.verbose = debug;

	/* server settings */
	test_init_server_settings(&http_server_set);
	http_server_set.ssl = &ssl_server_set;
	http_server_set.max_pipelined_requests = 4;

	/* client settings */
	test_init_client_settings(&http_client_set);
	http_client_set.ssl = &ssl_client_set;
	http_client_set.max_parallel_connections = 1;
	http_client_set.max_pipelined_requests = 8;

	test_run_client_server(&http_client_set, &http_server_set, client_init);

	test_out_reason("pipeline", (failure == NULL), failure);
}

static void
test_run_parallel(
	void (*client_init)(const struct http_client_settings *client_set))
{
	struct http_server_settings http_server_set;
	struct http_client_settings http_client_set;
	struct ssl_iostream_settings ssl_server_set, ssl_client_set;

	/* download files from blocking server */

	/* ssl settings */
	ssl_iostream_test_settings_server(&ssl_server_set);
	ssl_server_set.verbose = debug;
	ssl_iostream_test_settings_client(&ssl_client_set);
	ssl_client_set.verbose = debug;

	/* server settings */
	test_init_server_settings(&http_server_set);
	http_server_set.ssl = &ssl_server_set;
	http_server_set.max_pipelined_requests = 4;

	/* client settings */
	test_init_client_settings(&http_client_set);
	http_client_set.ssl = &ssl_client_set;
	http_client_set.max_parallel_connections = 40;
	http_client_set.max_pipelined_requests = 8;

	test_run_client_server(&http_client_set, &http_server_set, client_init);

	test_out_reason("parallel", (failure == NULL), failure);
}

static void test_download_server_nonblocking(void)
{
	test_begin("http payload download (server non-blocking)");
	test_init_defaults();
	test_run_sequential(test_client_download);
	test_run_pipeline(test_client_download);
	test_run_parallel(test_client_download);
	test_end();
}

static void test_download_server_blocking(void)
{
	test_begin("http payload download (server blocking)");
	test_init_defaults();
	tset.server_blocking = TRUE;
	test_run_sequential(test_client_download);
	test_run_pipeline(test_client_download);
	test_run_parallel(test_client_download);
	test_end();
}

static void test_echo_server_nonblocking(void)
{
	test_begin("http payload echo "
		   "(server non-blocking)");
	test_init_defaults();
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();

	test_begin("http payload echo "
		   "(server non-blocking; low-level)");
	test_init_defaults();
	tset.server_payload_handling = PAYLOAD_HANDLING_LOW_LEVEL;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();

	test_begin("http payload echo "
		   "(server non-blocking; handler)");
	test_init_defaults();
	tset.server_payload_handling = PAYLOAD_HANDLING_HANDLER;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();

	test_begin("http payload echo "
		   "(server non-blocking; size unknown)");
	test_init_defaults();
	tset.unknown_size = TRUE;
	tset.server_payload_handling = PAYLOAD_HANDLING_FORWARD;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();

	test_begin("http payload echo "
		   "(server non-blocking; ostream)");
	test_init_defaults();
	tset.server_ostream = TRUE;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();

	test_begin("http payload echo "
		   "(server non-blocking; ostream; cork)");
	test_init_defaults();
	tset.server_ostream = TRUE;
	tset.server_cork = TRUE;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();
}

static void test_echo_server_blocking(void)
{
	test_begin("http payload echo (server blocking)");
	test_init_defaults();
	tset.server_blocking = TRUE;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();

	test_begin("http payload echo (server blocking; ostream)");
	test_init_defaults();
	tset.server_blocking = TRUE;
	tset.server_ostream = TRUE;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();

	test_begin("http payload echo (server blocking; ostream; cork)");
	test_init_defaults();
	tset.server_ostream = TRUE;
	tset.server_blocking = TRUE;
	tset.server_cork = TRUE;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();
}

static void test_echo_server_nonblocking_sync(void)
{
	test_begin("http payload echo "
		   "(server non-blocking; 100-continue)");
	test_init_defaults();
	tset.request_100_continue = TRUE;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();

	test_begin("http payload echo "
		   "(server non-blocking; 100-continue; low-level)");
	test_init_defaults();
	tset.request_100_continue = TRUE;
	tset.server_payload_handling = PAYLOAD_HANDLING_LOW_LEVEL;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();

	test_begin("http payload echo "
		   "(server non-blocking; 100-continue; handler)");
	test_init_defaults();
	tset.request_100_continue = TRUE;
	tset.server_payload_handling = PAYLOAD_HANDLING_HANDLER;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();
}

static void test_echo_server_blocking_sync(void)
{
	test_begin("http payload echo (server blocking; 100-continue)");
	test_init_defaults();
	tset.server_blocking = TRUE;
	tset.request_100_continue = TRUE;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();

	test_begin("http payload echo "
		   "(server blocking; ostream; 100-continue)");
	test_init_defaults();
	tset.server_blocking = TRUE;
	tset.server_ostream = TRUE;
	tset.request_100_continue = TRUE;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();
}

static void test_echo_server_nonblocking_partial(void)
{
	test_begin("http payload echo "
		   "(server non-blocking; partial short)");
	test_init_defaults();
	tset.read_server_partial = 1024;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();
	test_begin("http payload echo "
		   "(server non-blocking; partial long)");
	test_init_defaults();
	tset.read_server_partial = IO_BLOCK_SIZE + 1024;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();

	test_begin("http payload echo (server non-blocking; "
		   "partial short; low-level)");
	test_init_defaults();
	tset.server_payload_handling = PAYLOAD_HANDLING_LOW_LEVEL;
	tset.read_server_partial = 1024;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();
	test_begin("http payload echo "
		   "(server non-blocking; partial long; low-level)");
	test_init_defaults();
	tset.server_payload_handling = PAYLOAD_HANDLING_LOW_LEVEL;
	tset.read_server_partial = IO_BLOCK_SIZE + 1024;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();

	test_begin("http payload echo "
		   "(server non-blocking; partial short; handler)");
	test_init_defaults();
	tset.server_payload_handling = PAYLOAD_HANDLING_HANDLER;
	tset.read_server_partial = 1024;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();
	test_begin("http payload echo "
		   "(server non-blocking; partial long; handler)");
	test_init_defaults();
	tset.server_payload_handling = PAYLOAD_HANDLING_HANDLER;
	tset.read_server_partial = IO_BLOCK_SIZE + 1024;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();

	test_begin("http payload echo "
		   "(server non-blocking; partial short; ostream)");
	test_init_defaults();
	tset.server_ostream = TRUE;
	tset.read_server_partial = 1024;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();
	test_begin("http payload echo "
		   "(server non-blocking; partial long; ostream)");
	test_init_defaults();
	tset.server_ostream = TRUE;
	tset.read_server_partial = IO_BLOCK_SIZE + 1024;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();

	test_begin("http payload echo "
		   "(server non-blocking; partial short; ostream; corked)");
	test_init_defaults();
	tset.server_ostream = TRUE;
	tset.server_cork = TRUE;
	tset.read_server_partial = 1024;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();
	test_begin("http payload echo "
		   "(server non-blocking; partial long; ostream; corked)");
	test_init_defaults();
	tset.server_ostream = TRUE;
	tset.server_cork = TRUE;
	tset.read_server_partial = IO_BLOCK_SIZE + 1024;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();
}

static void test_echo_server_blocking_partial(void)
{
	test_begin("http payload echo (server blocking; partial short)");
	test_init_defaults();
	tset.server_blocking = TRUE;
	tset.read_server_partial = 1024;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();
	test_begin("http payload echo (server blocking; partial long)");
	test_init_defaults();
	tset.server_blocking = TRUE;
	tset.read_server_partial = IO_BLOCK_SIZE + 1024;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();

	test_begin("http payload echo "
		   "(server blocking; partial short; ostream; cork)");
	test_init_defaults();
	tset.server_blocking = TRUE;
	tset.server_ostream = TRUE;
	tset.server_cork = TRUE;
	tset.read_server_partial = 1024;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();
	test_begin("http payload echo "
		   "(server blocking; partial long; ostream; cork)");
	test_init_defaults();
	tset.server_blocking = TRUE;
	tset.server_ostream = TRUE;
	tset.server_cork = TRUE;
	tset.read_server_partial = IO_BLOCK_SIZE + 1024;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();
}

static void test_download_client_partial(void)
{
	test_begin("http payload download (client partial)");
	test_init_defaults();
	tset.read_client_partial = 1024;
	test_run_sequential(test_client_download);
	test_run_pipeline(test_client_download);
	test_run_parallel(test_client_download);
	test_end();
	test_begin("http payload download (client partial long)");
	test_init_defaults();
	tset.read_client_partial = IO_BLOCK_SIZE + 1024;
	test_run_sequential(test_client_download);
	test_run_pipeline(test_client_download);
	test_run_parallel(test_client_download);
	test_end();
}

static void test_download_client_nested_ioloop(void)
{
	test_begin("http payload echo (client nested ioloop)");
	test_init_defaults();
	tset.client_ioloop_nesting = 10;
	test_run_parallel(test_client_echo);
	test_end();
}

static void test_echo_client_shared(void)
{
	test_begin("http payload download "
		   "(server non-blocking; client shared)");
	test_init_defaults();
	tset.parallel_clients = 4;
	test_run_sequential(test_client_download);
	tset.parallel_clients = 4;
	test_run_pipeline(test_client_download);
	tset.parallel_clients = 4;
	test_run_parallel(test_client_download);
	test_end();

	test_begin("http payload download "
		   "(server blocking; client shared)");
	test_init_defaults();
	tset.server_blocking = TRUE;
	tset.parallel_clients = 4;
	test_run_sequential(test_client_download);
	tset.parallel_clients = 4;
	test_run_pipeline(test_client_download);
	tset.parallel_clients = 4;
	test_run_parallel(test_client_download);
	test_end();

	test_begin("http payload echo "
		   "(server non-blocking; client shared)");
	test_init_defaults();
	tset.parallel_clients = 4;
	test_run_sequential(test_client_echo);
	tset.parallel_clients = 4;
	test_run_pipeline(test_client_echo);
	tset.parallel_clients = 4;
	test_run_parallel(test_client_echo);
	test_end();

	test_begin("http payload echo "
		   "(server blocking; client shared)");
	test_init_defaults();
	tset.server_blocking = TRUE;
	tset.server_ostream = TRUE;
	tset.parallel_clients = 4;
	test_run_sequential(test_client_echo);
	tset.parallel_clients = 4;
	test_run_pipeline(test_client_echo);
	tset.parallel_clients = 4;
	test_run_parallel(test_client_echo);
	test_end();

	test_begin("http payload echo "
		   "(server non-blocking; client global)");
	test_init_defaults();
	tset.parallel_clients = 4;
	tset.parallel_clients_global = TRUE;
	test_run_sequential(test_client_echo);
	tset.parallel_clients = 4;
	tset.parallel_clients_global = TRUE;
	test_run_pipeline(test_client_echo);
	tset.parallel_clients = 4;
	tset.parallel_clients_global = TRUE;
	test_run_parallel(test_client_echo);
	test_end();
}

#ifdef HAVE_OPENSSL
static void test_echo_ssl(void)
{
	test_begin("http payload echo (ssl)");
	test_init_defaults();
	tset.ssl = TRUE;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();

	test_begin("http payload echo (ssl; unknown size)");
	test_init_defaults();
	tset.unknown_size = TRUE;
	tset.ssl = TRUE;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();

	test_begin("http payload echo (ssl; server ostream, cork)");
	test_init_defaults();
	tset.ssl = TRUE;
	tset.server_ostream = TRUE;
	tset.server_cork = TRUE;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();
}
#endif

static void test_echo_client_blocking(void)
{
	test_begin("http payload echo (client blocking)");
	test_init_defaults();
	tset.client_blocking = TRUE;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();

	test_begin("http payload echo (client blocking; client shared)");
	test_init_defaults();
	tset.client_blocking = TRUE;
	tset.parallel_clients = 4;
	test_run_sequential(test_client_echo);
	tset.parallel_clients = 4;
	test_run_pipeline(test_client_echo);
	tset.parallel_clients = 4;
	test_run_parallel(test_client_echo);
	test_end();

	test_begin("http payload echo (client blocking; client global)");
	test_init_defaults();
	tset.client_blocking = TRUE;
	tset.parallel_clients = 4;
	tset.parallel_clients_global = TRUE;
	test_run_sequential(test_client_echo);
	tset.parallel_clients = 4;
	tset.parallel_clients_global = TRUE;
	test_run_pipeline(test_client_echo);
	tset.parallel_clients = 4;
	tset.parallel_clients_global = TRUE;
	test_run_parallel(test_client_echo);
	test_end();
}

static void (*const test_functions[])(void) = {
	test_download_server_nonblocking,
	test_download_server_blocking,
	test_echo_server_nonblocking,
	test_echo_server_blocking,
	test_echo_server_nonblocking_sync,
	test_echo_server_blocking_sync,
	test_echo_server_nonblocking_partial,
	test_echo_server_blocking_partial,
	test_download_client_partial,
	test_download_client_nested_ioloop,
	test_echo_client_shared,
#ifdef HAVE_OPENSSL
	test_echo_ssl,
#endif
	test_echo_client_blocking,
	NULL
};

/*
 * Main
 */

static void main_init(void)
{
#ifdef HAVE_OPENSSL
	ssl_iostream_openssl_init();
#endif
}

static void main_deinit(void)
{
	ssl_iostream_context_cache_free();
#ifdef HAVE_OPENSSL
	ssl_iostream_openssl_deinit();
#endif
}

int main(int argc, char *argv[])
{
	int c;
	int ret;

	lib_init();
	main_init();

	while ((c = getopt(argc, argv, "DS")) > 0) {
		switch (c) {
		case 'D':
			debug = TRUE;
			break;
		case 'S':
			small_socket_buffers = TRUE;
			break;
		default:
			i_fatal("Usage: %s [-D]", argv[0]);
		}
	}

	test_subprocesses_init(debug);

	/* listen on localhost */
	i_zero(&bind_ip);
	bind_ip.family = AF_INET;
	bind_ip.u.ip4.s_addr = htonl(INADDR_LOOPBACK);

	ret = test_run(test_functions);

	test_subprocesses_deinit();
	main_deinit();
	lib_deinit();
	return ret;
}
