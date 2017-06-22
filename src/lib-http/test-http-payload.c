/* Copyright (c) 2013-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "llist.h"
#include "abspath.h"
#include "hostpid.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "iostream-temp.h"
#include "connection.h"
#include "test-common.h"
#include "http-url.h"
#include "http-request.h"
#include "http-server.h"
#include "http-client.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

static bool debug = FALSE;

static bool blocking = FALSE;
static bool request_100_continue = FALSE;
static size_t read_server_partial = 0;
static size_t read_client_partial = 0;
static unsigned int test_max_pending = 200;
static unsigned int client_ioloop_nesting = 0;

static struct ip_addr bind_ip;
static in_port_t bind_port = 0;
static int fd_listen = -1;
static pid_t server_pid = (pid_t)-1;
static struct ioloop *ioloop_nested = NULL;
static unsigned ioloop_nested_first = 0;
static unsigned ioloop_nested_last = 0;

/*
 * Test files
 */

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
		if ((dp=readdir(dirp)) == NULL)
			break;
		if (*dp->d_name == '.')
			continue;

		file = t_abspath_to(dp->d_name, path);
		if (stat(file, &st) == 0) {
			if (S_ISREG(st.st_mode)) {
				file += 2; /* skip "./" */
				file = p_strdup(files_pool, file);
				array_append(&files, &file, 1);
			} else {
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
	files_pool = pool_alloconly_create
		(MEMPOOL_GROWING"http_server_request", 4096);
	p_array_init(&files, files_pool, 512);

	/* obtain all filenames */
	test_files_read_dir(".");
}

static void test_files_deinit(void)
{
	pool_unref(&files_pool);
}

static struct istream *
test_file_open(const char *path,
	unsigned int *status_r, const char **reason_r)
	ATTR_NULL(2, 3)
{
	int fd;

	if (status_r != NULL)
		*status_r = 200;
	if (reason_r != NULL)
		*reason_r = "OK";

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (debug) {
			i_debug("test files: "
				"open(%s) failed: %m", path);
		}
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

	return i_stream_create_fd(fd, 40960, TRUE);
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

	struct istream *payload_input;
	struct ostream *payload_output;
	struct io *io;
};

static const struct http_server_callbacks http_callbacks;
static struct http_server *http_server;

static struct io *io_listen;
static struct client *clients;

/* location: /succes */

static void
client_handle_success_request(struct client_request *creq)
{
	struct http_server_request *req = creq->server_req;
	const struct http_request *hreq =
		http_server_request_get(req);
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
client_handle_download_request(
	struct client_request *creq,
	const char *path)
{
	struct http_server_request *req = creq->server_req;
	const struct http_request *hreq =
		http_server_request_get(req);
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

	if (blocking) {
		output = http_server_response_get_payload_output(resp, TRUE);
		while ((ret=o_stream_send_istream	(output, fstream)) > 0);
		if (ret < 0) {
			i_fatal("test server: download: "
				"failed to send blocking file payload");
		}

		if (debug) {
			i_debug("test server: download: "
				"finished sending blocking payload for %s"
				"(%"PRIuUOFF_T":%"PRIuUOFF_T")",
				fpath, fstream->v_offset, output->offset);
		}

		o_stream_close(output);
		o_stream_unref(&output);
	} else {
		http_server_response_set_payload(resp, fstream);
		http_server_response_submit(resp);
	}
	i_stream_unref(&fstream);
}

/* location: /echo */

static void
client_request_read_echo_more(struct client_request *creq)
{
	struct http_server_response *resp;
	struct istream *payload_input;
	off_t ret;

	o_stream_set_max_buffer_size(creq->payload_output, IO_BLOCK_SIZE);
	ret = o_stream_send_istream(creq->payload_output, creq->payload_input);
	o_stream_set_max_buffer_size(creq->payload_output, (size_t)-1);
	if (ret < 0) {
		if (creq->payload_output->stream_errno != 0) {
			i_fatal("test server: echo: "
				"Failed to write all echo payload [%s]", creq->path);
		}
		if (creq->payload_input->stream_errno != 0) {
			i_fatal("test server: echo: "
				"Failed to read all echo payload [%s]", creq->path);
		}
		i_unreached();
	}
	if (i_stream_have_bytes_left(creq->payload_input))
		return;

	io_remove(&creq->io);
	i_stream_unref(&creq->payload_input);

	if (debug) {
		i_debug("test server: echo: "
			"finished receiving payload for %s", creq->path);
	}

	payload_input = iostream_temp_finish(&creq->payload_output, 4096);

	resp = http_server_response_create
		(creq->server_req, 200, "OK");
	http_server_response_add_header(resp, "Content-Type", "text/plain");
	http_server_response_set_payload(resp, payload_input);
	http_server_response_submit(resp);

	i_stream_unref(&payload_input);
}

static void
client_handle_echo_request(struct client_request *creq,
	const char *path)
{
	struct http_server_request *req = creq->server_req;
	const struct http_request *hreq =
		http_server_request_get(req);
	struct http_server_response *resp;
	struct ostream *payload_output;
	uoff_t size;
	int ret;

	creq->path = p_strdup
		(http_server_request_get_pool(req), path);

	if (strcmp(hreq->method, "PUT") != 0) {
		http_server_request_fail(req,
			405, "Method Not Allowed");
		return;
	}

	size = 0;
	(void)http_request_get_payload_size(hreq, &size);
	if (size == 0) {
		resp = http_server_response_create
			(creq->server_req, 200, "OK");
		http_server_response_add_header(resp, "Content-Type", "text/plain");
		http_server_response_submit(resp);
		return;
	}

	payload_output = iostream_temp_create
		("/tmp/test-http-server", 0);

	if (blocking) {
		struct istream *payload_input;

		payload_input =
			http_server_request_get_payload_input(req, TRUE);

		if (read_server_partial > 0) {
			struct istream *partial =
				i_stream_create_limit(payload_input, read_server_partial);
			i_stream_unref(&payload_input);
			payload_input = partial;
		}

		while ((ret=o_stream_send_istream
			(payload_output, payload_input)) > 0);
		if (ret < 0) {
			i_fatal("test server: echo: "
				"failed to receive blocking echo payload");
		}
		i_stream_unref(&payload_input);

		payload_input = iostream_temp_finish(&payload_output, 4096);

		if (debug) {
			i_debug("test server: echo: "
				"finished receiving blocking payload for %s", path);
		}

		resp = http_server_response_create(req, 200, "OK");
		http_server_response_add_header(resp, "Content-Type", "text/plain");

		payload_output = http_server_response_get_payload_output(resp, TRUE);
		while ((ret=o_stream_send_istream
			(payload_output, payload_input)) > 0);
		if (ret < 0) {
			i_fatal("test server: echo: "
				"failed to send blocking echo payload");
		}

		if (debug) {
			i_debug("test server: echo: "
				"finished sending blocking payload for %s", path);
		}

		i_stream_unref(&payload_input);
		o_stream_close(payload_output);
		o_stream_unref(&payload_output);

	} else {
		creq->payload_output = payload_output;
		creq->payload_input =
			http_server_request_get_payload_input(req, FALSE);

		if (read_server_partial > 0) {
			struct istream *partial =
				i_stream_create_limit(creq->payload_input, read_server_partial);
			i_stream_unref(&creq->payload_input);
			creq->payload_input = partial;
		}

		creq->io = io_add_istream(creq->payload_input,
				 client_request_read_echo_more, creq);
		client_request_read_echo_more(creq);
	}
}

/* request */

static void
http_server_request_destroyed(void *context);

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

	if (creq->io != NULL) {
		i_stream_unref(&creq->payload_input);
		io_remove(&creq->io);
	}

	http_server_request_unref(&req);
}

static void
http_server_request_destroyed(void *context)
{
	struct client_request *creq =
		(struct client_request *)context;

	client_request_deinit(&creq);
}

static void
client_handle_request(void *context,
	struct http_server_request *req)
{
	const struct http_request *hreq =
		http_server_request_get(req);
	const char *path = hreq->target.url->path, *p;
	struct client *client = (struct client *)context;
	struct client_request *creq;

	if (debug) {
		i_debug("test server: "
			"request method=`%s' path=`%s'", hreq->method, path);
	}

	creq = client_request_init(client, req);

	if (strcmp(path, "/success") == 0) {
		client_handle_success_request(creq);
		return;
	}

	if ((p=strchr(path+1, '/')) == NULL) {
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

static void
client_connection_destroy(void *context, const char *reason);

static const struct http_server_callbacks http_callbacks = {
	.connection_destroy = client_connection_destroy,
	.handle_request = client_handle_request
};

static void client_init(int fd)
{
	struct client *client;
	pool_t pool;

	net_set_nonblock(fd, TRUE);

	pool = pool_alloconly_create("client", 256);
	client = p_new(pool, struct client, 1);
	client->pool = pool;

	client->http_conn = http_server_connection_create(http_server,
		fd, fd, FALSE, &http_callbacks, client);
	DLLIST_PREPEND(&clients, client);
}

static void client_deinit(struct client **_client)
{
	struct client *client = *_client;

	*_client = NULL;

	DLLIST_REMOVE(&clients, client);

	if (client->http_conn != NULL)
		http_server_connection_close(&client->http_conn, "deinit");
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

	/* accept new client */
	fd = net_accept(fd_listen, NULL, NULL);
	if (fd == -1)
		return;
	if (fd == -2) {
		i_fatal("test server: accept() failed: %m");
	}

	client_init(fd);
}

/* */

static void
test_server_init(const struct http_server_settings *server_set)
{
	/* open server socket */
	io_listen = io_add(fd_listen,
		IO_READ, client_accept, (void *)NULL);

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
	struct test_client_request *prev, *next;
	struct http_client_request *hreq;

	struct io *io;
	struct istream *payload;
	struct istream *file;
	unsigned int files_idx;
};

static struct http_client *http_client;
static struct test_client_request *client_requests;
static unsigned int client_files_first, client_files_last;

static struct test_client_request *
test_client_request_new(void)
{
	struct test_client_request *tcreq;

	tcreq = i_new(struct test_client_request, 1);
	DLLIST_PREPEND(&client_requests, tcreq);

	return tcreq;
}

static void
test_client_request_destroy(void *context)
{
	struct test_client_request *tcreq =
		(struct test_client_request *)context;

	if (tcreq->io != NULL)
		io_remove(&tcreq->io);
	if (tcreq->payload != NULL)
		i_stream_unref(&tcreq->payload);
	if (tcreq->file != NULL)
		i_stream_unref(&tcreq->file);

	DLLIST_REMOVE(&client_requests, tcreq);
	i_free(tcreq);
}

static void
test_client_requests_switch_ioloop(void)
{
	struct test_client_request *tcreq;

	for (tcreq = client_requests; tcreq != NULL;
		tcreq = tcreq->next) {
		if (tcreq->io != NULL)
			tcreq->io = io_loop_move_io(&tcreq->io);
		if (tcreq->payload != NULL)
			i_stream_switch_ioloop(tcreq->payload);
	}
}

/* download */

static void test_client_download_continue(void);

static void
test_client_download_finished(unsigned int files_idx)
{
	const char **paths;
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
	unsigned int files_idx = tcreq->files_idx;
	off_t ret;

	/* read payload */
	while ((ret=i_stream_read_data
		(payload, &pdata, &psize, 0)) > 0) {
		if (debug) {
			i_debug("test client: download: "
				"got data for [%u] (size=%d)",
				tcreq->files_idx, (int)psize);
		}
		/* compare with file on disk */
		pleft = psize;
		while ((ret=i_stream_read_data
			(tcreq->file, &fdata, &fsize, 0)) > 0 && pleft > 0) {
			fsize = (fsize > pleft ? pleft : fsize);
			if (memcmp(pdata, fdata, fsize) != 0) {
				i_fatal("test client: download: "
					"received data does not match file "
					"(%"PRIuUOFF_T":%"PRIuUOFF_T")",
					payload->v_offset, tcreq->file->v_offset);
			}
			i_stream_skip(tcreq->file, fsize);
			pleft -= fsize;
			pdata += fsize;
		}
		if (ret < 0 && tcreq->file->stream_errno != 0) {
			i_fatal("test client: download: "
				"failed to read file: %s", i_stream_get_error(tcreq->file));
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
		(void)i_stream_read(tcreq->file);
		if (payload->stream_errno != 0) {
			i_fatal("test client: download: "
				"failed to read request payload: %s",
				i_stream_get_error(payload));
		} if (i_stream_have_bytes_left(tcreq->file)) {
			if (i_stream_read_data(tcreq->file, &fdata, &fsize, 0) <= 0)
				fsize = 0;
			i_fatal("test client: download: "
				"payload ended prematurely "
				"(at least %"PRIuSIZE_T" bytes left)", fsize);
		} else if (debug) {
			i_debug("test client: download: "
				"finished request for [%u]",
				tcreq->files_idx);
		}

		/* dereference payload stream; finishes the request */
		tcreq->payload = NULL;
		io_remove(&tcreq->io); /* holds a reference too */
		i_stream_unref(&payload);

		/* finished */
		test_client_download_finished(files_idx);
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
		i_debug("test client: download: "
			"got response for [%u]",
			tcreq->files_idx);
	}

	paths = array_get_modifiable(&files, &count);
	i_assert(tcreq->files_idx < count);
	i_assert(client_files_first < count);
	path = paths[tcreq->files_idx];
	i_assert(path != NULL);

	if (debug) {
		i_debug("test client: download: "
			"path for [%u]: %s",
			tcreq->files_idx, path);
	}

	fstream = test_file_open(path, &status, &reason);
	i_assert(fstream != NULL);

	if (status != resp->status) {
		i_fatal("test client: download: "
			"got wrong response for %s: %u %s (expected: %u %s)",
			path, resp->status, resp->reason, status, reason);
	}

	if (resp->status / 100 != 2) {
		if (debug) {
			i_debug("test client: download: "
				"HTTP request for %s failed: %u %s",
				path, resp->status, resp->reason);
		}
		i_stream_unref(&fstream);
		test_client_download_finished(tcreq->files_idx);
		return;
	}

	if (resp->payload == NULL) {
		if (debug) {
			i_debug("test client: download: "
				"no payload for %s [%u]",
				path, tcreq->files_idx);
		}
		i_stream_unref(&fstream);
		test_client_download_finished(tcreq->files_idx);
		return;
	}

	i_assert(fstream != NULL);
	if (read_client_partial == 0) {
		i_stream_ref(resp->payload);
		tcreq->payload = resp->payload;
		tcreq->file = fstream;
	} else {
		struct istream *payload = resp->payload;
		tcreq->payload = i_stream_create_limit
			(payload, read_client_partial);
		tcreq->file = i_stream_create_limit
			(fstream, read_client_partial);
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
		i_debug("test client: download: "
			"received until [%u]",
			client_files_first-1);
	}

	if (client_files_first >= count) {
		io_loop_stop(current_ioloop);
		return;
	}

	for (; client_files_last < count &&
			(client_files_last - client_files_first) < test_max_pending;
		client_files_last++) {
		const char *path = paths[client_files_last];

		tcreq = test_client_request_new();
		tcreq->files_idx = client_files_last;

		if (debug) {
			i_debug("test client: download: "
				"retrieving %s [%u]",
				path, tcreq->files_idx);
		}
		hreq = tcreq->hreq = http_client_request(http_client,
			"GET", net_ip2addr(&bind_ip),
			t_strconcat("/download/", path, NULL),
			test_client_download_response, tcreq);
		http_client_request_set_port(hreq, bind_port);
		http_client_request_set_destroy_callback(hreq,
			test_client_request_destroy, tcreq);
		http_client_request_submit(hreq);
	}
}

static void
test_client_download(const struct http_client_settings *client_set)
{
	/* create client */
	http_client = http_client_init(client_set);

	/* start querying server */
	client_files_first = client_files_last = 0;
	test_client_download_continue();
}

/* echo */

static void test_client_echo_continue(void);

static void
test_client_echo_finished(unsigned int files_idx)
{
	const char **paths;
	unsigned int count;

	paths = array_get_modifiable(&files, &count);
	i_assert(files_idx < count);
	i_assert(client_files_first < count);
	i_assert(paths[files_idx] != NULL);

	paths[files_idx] = NULL;
	test_client_echo_continue();
}

static void
test_client_echo_payload_input(struct test_client_request *tcreq)
{
	struct istream *payload = tcreq->payload;
	const unsigned char *pdata, *fdata;
	size_t psize, fsize, pleft;
	unsigned int files_idx = tcreq->files_idx;
	off_t ret;

	/* read payload */
	while ((ret=i_stream_read_data
		(payload, &pdata, &psize, 0)) > 0) {
		if (debug) {
			i_debug("test client: echo: "
				"got data for [%u] (size=%d)",
				tcreq->files_idx, (int)psize);
		}
		/* compare with file on disk */
		pleft = psize;
		while ((ret=i_stream_read_data
			(tcreq->file, &fdata, &fsize, 0)) > 0 && pleft > 0) {
			fsize = (fsize > pleft ? pleft : fsize);
			if (memcmp(pdata, fdata, fsize) != 0) {
				i_fatal("test client: echo: "
					"received data does not match file "
					"(%"PRIuUOFF_T":%"PRIuUOFF_T")",
					payload->v_offset, tcreq->file->v_offset);
			}
			i_stream_skip(tcreq->file, fsize);
			pleft -= fsize;
			pdata += fsize;
		}
		if (ret < 0 && tcreq->file->stream_errno != 0) {
			i_fatal("test client: echo: "
				"failed to read file: %s", i_stream_get_error(tcreq->file));
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
		(void)i_stream_read(tcreq->file);
		if (payload->stream_errno != 0) {
			i_fatal("test client: echo: "
				"failed to read request payload: %s",
				i_stream_get_error(payload));
		} if (i_stream_have_bytes_left(tcreq->file)) {
			if (i_stream_read_data(tcreq->file, &fdata, &fsize, 0) <= 0)
				fsize = 0;
			i_fatal("test client: echo: "
				"payload ended prematurely "
				"(at least %"PRIuSIZE_T" bytes left)", fsize);
		} else if (debug) {
			i_debug("test client: echo: "
				"finished request for [%u]",
				tcreq->files_idx);
		}

		/* dereference payload stream; finishes the request */
		tcreq->payload = NULL;
		io_remove(&tcreq->io); /* holds a reference too */
		i_stream_unref(&payload);

		/* finished */
		test_client_echo_finished(files_idx);
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
		i_debug("test client: echo: "
			"got response for [%u]",
			tcreq->files_idx);
	}

	paths = array_get_modifiable(&files, &count);
	i_assert(tcreq->files_idx < count);
	i_assert(client_files_first < count);
	path = paths[tcreq->files_idx];
	i_assert(path != NULL);

	if (debug) {
		i_debug("test client: echo: "
			"path for [%u]: %s",
			tcreq->files_idx, path);
	}

	if (resp->status / 100 != 2) {
		i_fatal("test client: echo: "
			"HTTP request for %s failed: %u %s",
			path, resp->status, resp->reason);
	}

	fstream = test_file_open(path, &status, NULL);
	if (fstream == NULL) {
		i_fatal("test client: echo: "
			"failed to open %s", path);
	}

	if (read_server_partial > 0) {
		struct istream *partial = i_stream_create_limit
			(fstream, read_server_partial);
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
		test_client_echo_finished(tcreq->files_idx);
		return;
	}

	i_assert(fstream != NULL);
	tcreq->file = fstream;

	i_stream_ref(resp->payload);
	tcreq->payload = resp->payload;
	tcreq->io = io_add_istream(resp->payload,
		test_client_echo_payload_input, tcreq);
	test_client_echo_payload_input(tcreq);
}

static void test_client_echo_continue(void)
{
	struct test_client_request *tcreq;
	struct http_client_request *hreq;
	const char **paths;
	unsigned int count, first_submitted;

	paths = array_get_modifiable(&files, &count);

	i_assert(client_files_first <= count);
	i_assert(client_files_last <= count);

	i_assert(client_files_first <= client_files_last);
	for (; client_files_first < client_files_last &&
		paths[client_files_first] == NULL; client_files_first++);

	if (debug) {
		i_debug("test client: echo: "
			"received until [%u/%u]", client_files_first-1, count);
	}

	if (debug && client_files_first < count) {
		const char *path = paths[client_files_first];
		i_debug("test client: echo: "
			"next blocking: %s [%d]",
			(path == NULL ? "none" : path),
			client_files_first);
	}

	if (client_files_first >= count) {
		io_loop_stop(current_ioloop);
		return;
	}

	first_submitted = client_files_last;
	for (; client_files_last < count &&
			(client_files_last - client_files_first) < test_max_pending;
		client_files_last++) {
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
			i_debug("test client: echo: "
				"retrieving %s [%u]",
				path, client_files_last);
		}

		tcreq = test_client_request_new();
		tcreq->files_idx = client_files_last;

		hreq = tcreq->hreq = http_client_request(http_client,
			"PUT", net_ip2addr(&bind_ip),
			t_strconcat("/echo/", path, NULL),
			test_client_echo_response, tcreq);
		http_client_request_set_port(hreq, bind_port);
		http_client_request_set_payload
			(hreq, fstream, request_100_continue);
		http_client_request_set_destroy_callback(hreq,
			test_client_request_destroy, tcreq);
		http_client_request_submit(hreq);

		i_stream_unref(&fstream);
	}

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
	} else if (client_ioloop_nesting > 0 &&
		((client_files_last / client_ioloop_nesting) !=
			(first_submitted / client_ioloop_nesting)) ) {
		struct ioloop *prev_ioloop = current_ioloop;

		ioloop_nested_first = first_submitted;
		ioloop_nested_last = first_submitted + client_ioloop_nesting;
		if (ioloop_nested_last > client_files_last)
			ioloop_nested_last = client_files_last;

		if (debug) {
			i_debug("test client: echo: entering ioloop for %u...%u",
				ioloop_nested_first, ioloop_nested_last);
		}

		ioloop_nested = io_loop_create();
		http_client_switch_ioloop(http_client);
		test_client_requests_switch_ioloop();

		io_loop_run(ioloop_nested);

		io_loop_set_current(prev_ioloop);
		http_client_switch_ioloop(http_client);
		test_client_requests_switch_ioloop();
		io_loop_set_current(ioloop_nested);
		io_loop_destroy(&ioloop_nested);
		ioloop_nested = NULL;

		if (debug) {
			i_debug("test client: echo: leaving ioloop for %u...%u",
				ioloop_nested_first, ioloop_nested_last);
		}
		ioloop_nested_first = ioloop_nested_last = 0;
	}
}

static void
test_client_echo(const struct http_client_settings *client_set)
{
	/* create client */
	http_client = http_client_init(client_set);

	/* start querying server */
	client_files_first = client_files_last = 0;
	test_client_echo_continue();
}

/* cleanup */

static void test_client_deinit(void)
{
	http_client_deinit(&http_client);
}

/*
 * Tests
 */

static void test_open_server_fd(void)
{
	if (fd_listen != -1)
		i_close_fd(&fd_listen);
	fd_listen = net_listen(&bind_ip, &bind_port, 128);
	if (fd_listen == -1) {
		i_fatal("listen(%s:%u) failed: %m",
			net_ip2addr(&bind_ip), bind_port);
	}
}

static void test_server_kill(void)
{
	if (server_pid != (pid_t)-1) {
		(void)kill(server_pid, SIGKILL);
		(void)waitpid(server_pid, NULL, 0);
	}
	server_pid = (pid_t)-1;
}

static void test_run_client_server(
	const struct http_client_settings *client_set,
	const struct http_server_settings *server_set,
	void (*client_init)(const struct http_client_settings *client_set))
{
	struct ioloop *ioloop;

	test_open_server_fd();

	if ((server_pid = fork()) == (pid_t)-1)
		i_fatal("fork() failed: %m");
	if (server_pid == 0) {
		server_pid = (pid_t)-1;
		hostpid_init();
		if (debug)
			i_debug("server: PID=%s", my_pid);
		/* child: server */
		ioloop_nested = FALSE;
		ioloop = io_loop_create();
		test_server_init(server_set);
		io_loop_run(ioloop);
		test_server_deinit();
		io_loop_destroy(&ioloop);
		i_close_fd(&fd_listen);
	} else {
		if (debug)
			i_debug("client: PID=%s", my_pid);
		i_close_fd(&fd_listen);
		/* parent: client */
		ioloop_nested = FALSE;
		ioloop = io_loop_create();
		client_init(client_set);
		io_loop_run(ioloop);
		test_client_deinit();
		io_loop_destroy(&ioloop);
		test_server_kill();
	}
}

static void test_run_sequential(
	void (*client_init)(const struct http_client_settings *client_set))
{
	struct http_server_settings http_server_set;
	struct http_client_settings http_client_set;

	/* download files from blocking server */

	/* server settings */
	i_zero(&http_server_set);
	http_server_set.max_pipelined_requests = 0;
	http_server_set.debug = debug;
	http_server_set.request_limits.max_payload_size = (uoff_t)-1;

	/* client settings */
	i_zero(&http_client_set);
	http_client_set.max_idle_time_msecs = 5*1000;
	http_client_set.max_parallel_connections = 1;
	http_client_set.max_pipelined_requests = 1;
	http_client_set.max_redirects = 0;
	http_client_set.max_attempts = 1;
	http_client_set.debug = debug;

	test_files_init();
	test_run_client_server
		(&http_client_set, &http_server_set, client_init);
	test_files_deinit();

	test_out("sequential", TRUE);
}

static void test_run_pipeline(
	void (*client_init)(const struct http_client_settings *client_set))
{
	struct http_server_settings http_server_set;
	struct http_client_settings http_client_set;

	/* download files from blocking server */

	/* server settings */
	i_zero(&http_server_set);
	http_server_set.max_pipelined_requests = 4;
	http_server_set.debug = debug;
	http_server_set.request_limits.max_payload_size = (uoff_t)-1;

	/* client settings */
	i_zero(&http_client_set);
	http_client_set.max_idle_time_msecs = 5*1000;
	http_client_set.max_parallel_connections = 1;
	http_client_set.max_pipelined_requests = 8;
	http_client_set.max_redirects = 0;
	http_client_set.max_attempts = 1;
	http_client_set.debug = debug;

	test_files_init();
	test_run_client_server
		(&http_client_set, &http_server_set, client_init);
	test_files_deinit();

	test_out("pipeline", TRUE);
}

static void test_run_parallel(
	void (*client_init)(const struct http_client_settings *client_set))
{
	struct http_server_settings http_server_set;
	struct http_client_settings http_client_set;

	/* download files from blocking server */

	/* server settings */
	i_zero(&http_server_set);
	http_server_set.max_pipelined_requests = 4;
	http_server_set.debug = debug;
	http_server_set.request_limits.max_payload_size = (uoff_t)-1;

	/* client settings */
	i_zero(&http_client_set);
	http_client_set.max_idle_time_msecs = 5*1000;
	http_client_set.max_parallel_connections = 40;
	http_client_set.max_pipelined_requests = 8;
	http_client_set.max_redirects = 0;
	http_client_set.max_attempts = 1;
	http_client_set.debug = debug;

	test_files_init();
	test_run_client_server
		(&http_client_set, &http_server_set, client_init);
	test_files_deinit();

	test_out("parallel", TRUE);
}

static void test_download_server_nonblocking(void)
{
	test_begin("http payload download (server non-blocking)");
	blocking = FALSE;
	request_100_continue = FALSE;
	read_server_partial = 0;
	client_ioloop_nesting = 0;
	test_run_sequential(test_client_download);
	test_run_pipeline(test_client_download);
	test_run_parallel(test_client_download);
	test_end();
}

static void test_download_server_blocking(void)
{
	test_begin("http payload download (server blocking)");
	blocking = TRUE;
	request_100_continue = FALSE;
	read_server_partial = 0;
	client_ioloop_nesting = 0;
	test_run_sequential(test_client_download);
	test_run_pipeline(test_client_download);
	test_run_parallel(test_client_download);
	test_end();
}

static void test_echo_server_nonblocking(void)
{
	test_begin("http payload echo (server non-blocking)");
	blocking = FALSE;
	request_100_continue = FALSE;
	read_server_partial = 0;
	client_ioloop_nesting = 0;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();
}

static void test_echo_server_blocking(void)
{
	test_begin("http payload echo (server blocking)");
	blocking = TRUE;
	request_100_continue = FALSE;
	read_server_partial = 0;
	client_ioloop_nesting = 0;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();
}

static void test_echo_server_nonblocking_sync(void)
{
	test_begin("http payload echo (server non-blocking; 100-continue)");
	blocking = FALSE;
	request_100_continue = TRUE;
	read_server_partial = 0;
	client_ioloop_nesting = 0;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();
}

static void test_echo_server_blocking_sync(void)
{
	test_begin("http payload echo (server blocking; 100-continue)");
	blocking = TRUE;
	request_100_continue = TRUE;
	read_server_partial = 0;
	client_ioloop_nesting = 0;
  test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();
}

static void test_echo_server_nonblocking_partial(void)
{
	test_begin("http payload echo (server non-blocking; partial short)");
	blocking = FALSE;
	request_100_continue = FALSE;
	read_server_partial = 1024;
	client_ioloop_nesting = 0;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();
	test_begin("http payload echo (server non-blocking; partial long)");
	read_server_partial = IO_BLOCK_SIZE + 1024;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();
}

static void test_echo_server_blocking_partial(void)
{
	test_begin("http payload echo (server blocking; partial short)");
	blocking = TRUE;
	request_100_continue = FALSE;
	read_server_partial = 1024;
	client_ioloop_nesting = 0;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();
	test_begin("http payload echo (server blocking; partial long)");
	read_server_partial = IO_BLOCK_SIZE + 1024;
	test_run_sequential(test_client_echo);
	test_run_pipeline(test_client_echo);
	test_run_parallel(test_client_echo);
	test_end();
}

static void test_download_client_partial(void)
{
	test_begin("http payload download (client partial)");
	blocking = FALSE;
	request_100_continue = FALSE;
	read_server_partial = 0;
	read_client_partial = 1024;
	client_ioloop_nesting = 0;
	test_run_sequential(test_client_download);
	test_run_pipeline(test_client_download);
	test_run_parallel(test_client_download);
	test_end();
	test_begin("http payload download (client partial long)");
	blocking = FALSE;
	request_100_continue = FALSE;
	read_server_partial = 0;
	read_client_partial = IO_BLOCK_SIZE + 1024;
	test_run_sequential(test_client_download);
	test_run_pipeline(test_client_download);
	test_run_parallel(test_client_download);
	test_end();
}

static void test_download_client_nested_ioloop(void)
{
	test_begin("http payload echo (client nested ioloop)");
	blocking = FALSE;
	request_100_continue = FALSE;
	read_server_partial = 0;
	read_client_partial = 0;
	client_ioloop_nesting = 10;
	test_run_parallel(test_client_echo);
	test_end();
}

static void (*test_functions[])(void) = {
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
	NULL
};

/*
 * Main
 */

volatile sig_atomic_t terminating = 0;

static void
test_signal_handler(int signo)
{
	if (terminating)
		raise(signo);
	terminating = 1;

	/* make sure we don't leave any pesky children alive */
	test_server_kill();

	(void)signal(signo, SIG_DFL);
	raise(signo);
}

static void test_atexit(void)
{
	test_server_kill();
}

int main(int argc, char *argv[])
{
	int c;

	atexit(test_atexit);
	(void)signal(SIGCHLD, SIG_IGN);
	(void)signal(SIGTERM, test_signal_handler);
	(void)signal(SIGQUIT, test_signal_handler);
	(void)signal(SIGINT, test_signal_handler);
	(void)signal(SIGSEGV, test_signal_handler);
	(void)signal(SIGABRT, test_signal_handler);

  while ((c = getopt(argc, argv, "D")) > 0) {
		switch (c) {
		case 'D':
			debug = TRUE;
			break;
		default:
			i_fatal("Usage: %s [-D]", argv[0]);
		}
  }

	/* listen on localhost */
	i_zero(&bind_ip);
	bind_ip.family = AF_INET;
	bind_ip.u.ip4.s_addr = htonl(INADDR_LOOPBACK);

	test_run(test_functions);
}
