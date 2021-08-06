/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "str.h"
#include "strescape.h"
#include "ioloop.h"
#include "istream.h"
#include "http-url.h"
#include "http-client.h"
#include "fts-solr-plugin.h"
#include "solr-connection.h"

#include <expat.h>

struct solr_lookup_context {
	pool_t result_pool;
	struct istream *payload;
	struct io *io;

	int request_status;

	struct solr_response_parser *parser;
	struct solr_result **results;
};

struct solr_connection_post {
	struct solr_connection *conn;

	struct http_client_request *http_req;
	int request_status;

	bool failed:1;
};

struct solr_connection {
	struct event *event;
	char *http_host;
	in_port_t http_port;
	char *http_base_url;
	char *http_failure;
	char *http_user;
	char *http_password;

	bool debug:1;
	bool posting:1;
	bool http_ssl:1;
};

/* Regardless of the specified URL, make sure path ends in '/' */
static char *solr_connection_create_http_base_url(struct http_url *http_url)
{
	if (http_url->path == NULL)
		return i_strconcat("/", http_url->enc_query, NULL);
	size_t len = strlen(http_url->path);
	if (len > 0 && http_url->path[len-1] != '/')
		return i_strconcat(http_url->path, "/",
				   http_url->enc_query, NULL);
	/* http_url->path is NULL on empty path, so this is impossible. */
	i_assert(len != 0);
	return i_strconcat(http_url->path, http_url->enc_query, NULL);
}

int solr_connection_init(const struct fts_solr_settings *solr_set,
			 const struct ssl_iostream_settings *ssl_client_set,
			 struct event *event_parent,
			 struct solr_connection **conn_r, const char **error_r)
{
	struct http_client_settings http_set;
	struct solr_connection *conn;
	struct http_url *http_url;
	const char *error;

	if (http_url_parse(solr_set->url, NULL, HTTP_URL_ALLOW_USERINFO_PART,
			   pool_datastack_create(), &http_url, &error) < 0) {
		*error_r = t_strdup_printf(
			"fts_solr: Failed to parse HTTP url: %s", error);
		return -1;
	}

	conn = i_new(struct solr_connection, 1);
	conn->event = event_create(event_parent);
	conn->http_host = i_strdup(http_url->host.name);
	conn->http_port = http_url->port;
	conn->http_base_url = solr_connection_create_http_base_url(http_url);
	conn->http_ssl = http_url->have_ssl;
	if (http_url->user != NULL) {
		conn->http_user = i_strdup(http_url->user);
		/* allow empty password */
		conn->http_password = i_strdup(http_url->password != NULL ?
					       http_url->password : "");
	}

	conn->debug = solr_set->debug;

	if (solr_http_client == NULL) {
		i_zero(&http_set);
		http_set.max_idle_time_msecs = 5*1000;
		http_set.max_parallel_connections = 1;
		http_set.max_pipelined_requests = 1;
		http_set.max_redirects = 1;
		http_set.max_attempts = 3;
		http_set.connect_timeout_msecs = 5*1000;
		http_set.request_timeout_msecs = 60*1000;
		http_set.ssl = ssl_client_set;
		http_set.debug = solr_set->debug;
		http_set.rawlog_dir = solr_set->rawlog_dir;
		http_set.event_parent = conn->event;

		/* FIXME: We should initialize a shared client instead. However,
		          this is currently not possible due to an obscure bug
		          in the blocking HTTP payload API, which causes
		          conflicts with other HTTP applications like FTS Tika.
		          Using a private client will provide a quick fix for
		          now. */
		solr_http_client = http_client_init_private(&http_set);
	}

	*conn_r = conn;
	return 0;
}

void solr_connection_deinit(struct solr_connection **_conn)
{
	struct solr_connection *conn = *_conn;

	*_conn = NULL;
	event_unref(&conn->event);
	i_free(conn->http_host);
	i_free(conn->http_base_url);
	i_free(conn->http_user);
	i_free(conn->http_password);
	i_free(conn);
}

static void solr_connection_payload_input(struct solr_lookup_context *lctx)
{
	int ret;

	/* read payload */
	ret = solr_response_parse(lctx->parser, &lctx->results);

	if (ret == 0) {
		/* we will be called again for more data */
	} else {
		if (lctx->payload->stream_errno != 0) {
			i_assert(ret < 0);
			i_error("fts_solr: "
				"failed to read payload from HTTP server: %s",
				i_stream_get_error(lctx->payload));
		}
		if (ret < 0)
			lctx->request_status = -1;
		solr_response_parser_deinit(&lctx->parser);
		io_remove(&lctx->io);
	}
}

static void
solr_connection_select_response(const struct http_response *response,
				struct solr_lookup_context *lctx)
{
	if (response->status / 100 != 2) {
		i_error("fts_solr: Lookup failed: %s",
			http_response_get_message(response));
		lctx->request_status = -1;
		return;
	}

	if (response->payload == NULL) {
		i_error("fts_solr: Lookup failed: Empty response payload");
		lctx->request_status = -1;
		return;
	}

	lctx->parser = solr_response_parser_init(lctx->result_pool,
						 response->payload);
	lctx->payload = response->payload;
	lctx->io = io_add_istream(response->payload,
				  solr_connection_payload_input, lctx);
	solr_connection_payload_input(lctx);
}

int solr_connection_select(struct solr_connection *conn, const char *query,
			   pool_t pool, struct solr_result ***box_results_r)
{
	struct solr_lookup_context lctx;
	struct http_client_request *http_req;
	const char *url;

	i_zero(&lctx);
	lctx.result_pool = pool;

	i_free_and_null(conn->http_failure);
	url = t_strconcat(conn->http_base_url, "select?", query, NULL);

	http_req = http_client_request(solr_http_client, "GET",
				       conn->http_host, url,
				       solr_connection_select_response,
				       &lctx);
	if (conn->http_user != NULL) {
		http_client_request_set_auth_simple(
			http_req, conn->http_user, conn->http_password);
	}
	http_client_request_set_port(http_req, conn->http_port);
	http_client_request_set_ssl(http_req, conn->http_ssl);
	http_client_request_submit(http_req);

	lctx.request_status = 0;
	http_client_wait(solr_http_client);

	if (lctx.request_status < 0)
		return -1;

	*box_results_r = lctx.results;
	return 0;
}

static void
solr_connection_update_response(const struct http_response *response,
				struct solr_connection_post *post)
{
	if (response->status / 100 != 2) {
		i_error("fts_solr: Indexing failed: %s",
			http_response_get_message(response));
		post->request_status = -1;
	}
}

static struct http_client_request *
solr_connection_post_request(struct solr_connection_post *post)
{
	struct solr_connection *conn = post->conn;
	struct http_client_request *http_req;
	const char *url;

	url = t_strconcat(conn->http_base_url, "update", NULL);

	http_req = http_client_request(solr_http_client, "POST",
				       conn->http_host, url,
				       solr_connection_update_response, post);
	if (conn->http_user != NULL) {
		http_client_request_set_auth_simple(
			http_req, conn->http_user, conn->http_password);
	}
	http_client_request_set_port(http_req, conn->http_port);
	http_client_request_set_ssl(http_req, conn->http_ssl);
	http_client_request_add_header(http_req, "Content-Type", "text/xml");
	return http_req;
}

struct solr_connection_post *
solr_connection_post_begin(struct solr_connection *conn)
{
	struct solr_connection_post *post;

	i_assert(!conn->posting);
	conn->posting = TRUE;

	post = i_new(struct solr_connection_post, 1);
	post->conn = conn;
	post->http_req = solr_connection_post_request(post);
	return post;
}

void solr_connection_post_more(struct solr_connection_post *post,
			       const unsigned char *data, size_t size)
{
	i_assert(post->conn->posting);

	if (post->failed)
		return;

	if (post->request_status == 0) {
		(void)http_client_request_send_payload(
			&post->http_req, data, size);
	}
	if (post->request_status < 0)
		post->failed = TRUE;
}

int solr_connection_post_end(struct solr_connection_post **_post)
{
	struct solr_connection_post *post = *_post;
	struct solr_connection *conn = post->conn;
	int ret = post->failed ? -1 : 0;

	i_assert(conn->posting);

	*_post = NULL;

	if (!post->failed) {
		if (http_client_request_finish_payload(&post->http_req) < 0 ||
		    post->request_status < 0) {
			ret = -1;
		}
	} else {
		http_client_request_abort(&post->http_req);
	}
	i_free(post);

	conn->posting = FALSE;
	return ret;
}

int solr_connection_post(struct solr_connection *conn, const char *cmd)
{
	struct istream *post_payload;
	struct solr_connection_post post;

	i_assert(!conn->posting);

	i_zero(&post);
	post.conn = conn;

	post.http_req = solr_connection_post_request(&post);
	post_payload = i_stream_create_from_data(cmd, strlen(cmd));
	http_client_request_set_payload(post.http_req, post_payload, TRUE);
	i_stream_unref(&post_payload);
	http_client_request_submit(post.http_req);

	post.request_status = 0;
	http_client_wait(solr_http_client);

	return post.request_status;
}
