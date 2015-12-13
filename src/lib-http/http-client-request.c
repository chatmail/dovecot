/* Copyright (c) 2013-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "str.h"
#include "hash.h"
#include "array.h"
#include "llist.h"
#include "time-util.h"
#include "istream.h"
#include "ostream.h"
#include "dns-lookup.h"
#include "http-url.h"
#include "http-date.h"
#include "http-auth.h"
#include "http-response-parser.h"
#include "http-transfer.h"

#include "http-client-private.h"

const char *http_request_state_names[] = {
	"new",
	"queued",
	"payload_out",
	"waiting",
	"got_response",
	"payload_in",
	"finished",
	"aborted"
};

/*
 * Logging
 */

static inline void
http_client_request_debug(struct http_client_request *req,
	const char *format, ...) ATTR_FORMAT(2, 3);

static inline void
http_client_request_debug(struct http_client_request *req,
	const char *format, ...)
{
	va_list args;

	if (req->client->set.debug) {
		va_start(args, format);	
		i_debug("http-client: request %s: %s",
			http_client_request_label(req), t_strdup_vprintf(format, args));
		va_end(args);
	}
}

/*
 * Request
 */

static void
http_client_request_send_error(struct http_client_request *req,
			       unsigned int status, const char *error);

static struct http_client_request *
http_client_request_new(struct http_client *client, const char *method, 
		    http_client_request_callback_t *callback, void *context)
{
	pool_t pool;
	struct http_client_request *req;

	pool = pool_alloconly_create("http client request", 2048);
	req = p_new(pool, struct http_client_request, 1);
	req->pool = pool;
	req->refcount = 1;
	req->client = client;
	req->method = p_strdup(pool, method);
	req->callback = callback;
	req->context = context;
	req->date = (time_t)-1;

	req->state = HTTP_REQUEST_STATE_NEW;
	return req;
}

#undef http_client_request
struct http_client_request *
http_client_request(struct http_client *client,
		    const char *method, const char *host, const char *target,
		    http_client_request_callback_t *callback, void *context)
{
	struct http_client_request *req;

	req = http_client_request_new(client, method, callback, context);
	req->origin_url.host_name = p_strdup(req->pool, host);
	req->target = (target == NULL ? "/" : p_strdup(req->pool, target));
	return req;
}

#undef http_client_request_url
struct http_client_request *
http_client_request_url(struct http_client *client,
		    const char *method, const struct http_url *target_url,
		    http_client_request_callback_t *callback, void *context)
{
	struct http_client_request *req;

	req = http_client_request_new(client, method, callback, context);
	http_url_copy_authority(req->pool, &req->origin_url, target_url);
	req->target = p_strdup(req->pool, http_url_create_target(target_url));
	if (target_url->user != NULL && *target_url->user != '\0' &&
		target_url->password != NULL) {
		req->username = p_strdup(req->pool, target_url->user);
		req->password = p_strdup(req->pool, target_url->password);
	}
	return req;
}

#undef http_client_request_connect
struct http_client_request *
http_client_request_connect(struct http_client *client,
		    const char *host, in_port_t port,
		    http_client_request_callback_t *callback,
				void *context)
{
	struct http_client_request *req;

	req = http_client_request_new(client, "CONNECT", callback, context);
	req->origin_url.host_name = p_strdup(req->pool, host);
	req->origin_url.port = port;
	req->origin_url.have_port = TRUE;
	req->connect_tunnel = TRUE;
	req->target = req->origin_url.host_name;
	return req;
}

#undef http_client_request_connect_ip
struct http_client_request *
http_client_request_connect_ip(struct http_client *client,
		    const struct ip_addr *ip, in_port_t port,
		    http_client_request_callback_t *callback,
				void *context)
{
	struct http_client_request *req;
	const char *hostname = net_ip2addr(ip);

	req = http_client_request_connect
		(client, hostname, port, callback, context);
	req->origin_url.host_ip = *ip;
	req->origin_url.have_host_ip = TRUE;
	return req;
}

void http_client_request_ref(struct http_client_request *req)
{
	i_assert(req->refcount > 0);
	req->refcount++;
}

void http_client_request_unref(struct http_client_request **_req)
{
	struct http_client_request *req = *_req;
	struct http_client *client = req->client;

	i_assert(req->refcount > 0);

	if (--req->refcount > 0)
		return;

	/* cannot be destroyed while it is still pending */
	i_assert(req->conn == NULL || req->conn->pending_request == NULL);

	if (req->queue != NULL)
		http_client_queue_drop_request(req->queue, req);

	if (req->destroy_callback != NULL) {
		req->destroy_callback(req->destroy_context);
		req->destroy_callback = NULL;
	}

	/* only decrease pending request counter if this request was submitted */
	if (req->submitted) {
		DLLIST_REMOVE(&client->requests_list, req);
		client->requests_count--;
	}

	http_client_request_debug(req, "Destroy (requests left=%d)",
		client->requests_count);

	if (req->queue != NULL)
		http_client_queue_drop_request(req->queue, req);

	if (client->requests_count == 0 && client->ioloop != NULL)
		io_loop_stop(client->ioloop);

	if (req->delayed_error != NULL)
		http_client_remove_request_error(req->client, req);
	if (req->payload_input != NULL)
		i_stream_unref(&req->payload_input);
	if (req->payload_output != NULL)
		o_stream_unref(&req->payload_output);
	if (req->headers != NULL)
		str_free(&req->headers);
	pool_unref(&req->pool);
	*_req = NULL;
}

void http_client_request_set_port(struct http_client_request *req,
	in_port_t port)
{
	i_assert(req->state == HTTP_REQUEST_STATE_NEW);
	req->origin_url.port = port;
	req->origin_url.have_port = TRUE;
}

void http_client_request_set_ssl(struct http_client_request *req,
	bool ssl)
{
	i_assert(req->state == HTTP_REQUEST_STATE_NEW);
	req->origin_url.have_ssl = ssl;
}

void http_client_request_set_urgent(struct http_client_request *req)
{
	i_assert(req->state == HTTP_REQUEST_STATE_NEW);
	req->urgent = TRUE;
}

void http_client_request_add_header(struct http_client_request *req,
				    const char *key, const char *value)
{
	i_assert(req->state == HTTP_REQUEST_STATE_NEW ||
		 /* allow calling for retries */
		 req->state == HTTP_REQUEST_STATE_GOT_RESPONSE ||
		 req->state == HTTP_REQUEST_STATE_ABORTED);

	/* mark presence of special headers */
	switch (key[0]) {
	case 'a': case 'A':
		if (strcasecmp(key, "Authorization") == 0)
			req->have_hdr_authorization = TRUE;
		break;
	case 'c': case 'C':
		if (strcasecmp(key, "Connection") == 0)
			req->have_hdr_connection = TRUE;
		else 	if (strcasecmp(key, "Content-Length") == 0)
			req->have_hdr_body_spec = TRUE;
		break;
	case 'd': case 'D':
		if (strcasecmp(key, "Date") == 0)
			req->have_hdr_date = TRUE;
		break;
	case 'e': case 'E':
		if (strcasecmp(key, "Expect") == 0)
			req->have_hdr_expect = TRUE;
		break;
	case 'h': case 'H':
		if (strcasecmp(key, "Host") == 0)
			req->have_hdr_host = TRUE;
		break;
	case 'p': case 'P':
		i_assert(strcasecmp(key, "Proxy-Authorization") != 0);
		break;
	case 't': case 'T':
		if (strcasecmp(key, "Transfer-Encoding") == 0)
			req->have_hdr_body_spec = TRUE;
		break;
	case 'u': case 'U':
		if (strcasecmp(key, "User-Agent") == 0)
			req->have_hdr_user_agent = TRUE;
		break;
	}
	if (req->headers == NULL)
		req->headers = str_new(default_pool, 256);
	str_printfa(req->headers, "%s: %s\r\n", key, value);
}

void http_client_request_remove_header(struct http_client_request *req,
				       const char *key)
{
	const unsigned char *data, *p;
	size_t size, line_len, line_start_pos;
	unsigned int key_len = strlen(key);

	i_assert(req->state == HTTP_REQUEST_STATE_NEW ||
		 /* allow calling for retries */
		 req->state == HTTP_REQUEST_STATE_GOT_RESPONSE ||
		 req->state == HTTP_REQUEST_STATE_ABORTED);

	data = str_data(req->headers);
	size = str_len(req->headers);
	while ((p = memchr(data, '\n', size)) != NULL) {
		line_len = (p+1) - data;
		if (size > key_len && i_memcasecmp(data, key, key_len) == 0 &&
		    data[key_len] == ':' && data[key_len+1] == ' ') {
			/* key was found from header, replace its value */
			line_start_pos = str_len(req->headers) - size;
			str_delete(req->headers, line_start_pos, line_len);
			break;
		}
		size -= line_len;
		data += line_len;
	}
}

void http_client_request_set_date(struct http_client_request *req,
				    time_t date)
{
	i_assert(req->state == HTTP_REQUEST_STATE_NEW);
	req->date = date;
}

void http_client_request_set_payload(struct http_client_request *req,
				     struct istream *input, bool sync)
{
	int ret;

	i_assert(req->state == HTTP_REQUEST_STATE_NEW);
	i_assert(req->payload_input == NULL);

	i_stream_ref(input);
	req->payload_input = input;
	if ((ret = i_stream_get_size(input, TRUE, &req->payload_size)) <= 0) {
		if (ret < 0) {
			i_error("i_stream_get_size(%s) failed: %s",
				i_stream_get_name(input),
				i_stream_get_error(input));
		}
		req->payload_size = 0;
		req->payload_chunked = TRUE;
	}
	req->payload_offset = input->v_offset;

	/* prepare request payload sync using 100 Continue response from server */
	if ((req->payload_chunked || req->payload_size > 0) && sync)
		req->payload_sync = TRUE;
}

void http_client_request_set_timeout_msecs(struct http_client_request *req,
	unsigned int msecs)
{
	i_assert(req->state == HTTP_REQUEST_STATE_NEW ||
		req->state == HTTP_REQUEST_STATE_GOT_RESPONSE);

	req->timeout_msecs = msecs;
}

void http_client_request_set_timeout(struct http_client_request *req,
	const struct timeval *time)
{
	i_assert(req->state == HTTP_REQUEST_STATE_NEW ||
		req->state == HTTP_REQUEST_STATE_GOT_RESPONSE);

	req->timeout_time = *time;
	req->timeout_msecs = 0;
}

void http_client_request_set_auth_simple(struct http_client_request *req,
	const char *username, const char *password)
{
	req->username = p_strdup(req->pool, username);
	req->password = p_strdup(req->pool, password);
}

void http_client_request_delay_until(struct http_client_request *req,
	time_t time)
{
	req->release_time.tv_sec = time;
	req->release_time.tv_usec = 0;
}

void http_client_request_delay(struct http_client_request *req,
	time_t seconds)
{
	req->release_time = ioloop_timeval;
	req->release_time.tv_sec += seconds;
}

void http_client_request_delay_msecs(struct http_client_request *req,
	unsigned int msecs)
{
	req->release_time = ioloop_timeval;
	timeval_add_msecs(&req->release_time, msecs);
}

int http_client_request_delay_from_response(struct http_client_request *req,
	const struct http_response *response)
{
	time_t retry_after = response->retry_after;
	unsigned int max;

	if (retry_after == (time_t)-1)
		return 0;  /* no delay */
	if (retry_after < ioloop_time)
		return 0;  /* delay already expired */
	max = (req->client->set.max_auto_retry_delay == 0 ?
		req->client->set.request_timeout_msecs / 1000 :
		req->client->set.max_auto_retry_delay);
	if ((unsigned int)(retry_after - ioloop_time) > max)
		return -1; /* delay too long */
	req->release_time.tv_sec = retry_after;
	req->release_time.tv_usec = 0;
	return 1;    /* valid delay */
}

const char *http_client_request_get_method(struct http_client_request *req)
{
	return req->method;
}

const char *http_client_request_get_target(struct http_client_request *req)
{
	return req->target;
}

enum http_request_state
http_client_request_get_state(struct http_client_request *req)
{
	return req->state;
}

enum http_response_payload_type
http_client_request_get_payload_type(struct http_client_request *req)
{
	/* RFC 7230, Section 3.3:

		 The presence of a message body in a response depends on both the
		 request method to which it is responding and the response status code
		 (Section 3.1.2 of [RFC7230]). Responses to the HEAD request method
	   (Section 4.3.2 of [RFC7231]) never include a message body because the
	   associated response header fields (e.g., Transfer-Encoding,
	   Content-Length, etc.), if present, indicate only what their values
	   would have been if the request method had been GET (Section 4.3.1 of
	   [RFC7231]). 2xx (Successful) responses to a CONNECT request method
	   (Section 4.3.6 of [RFC7231]) switch to tunnel mode instead of having a
	   message body.
	 */
	if (strcmp(req->method, "HEAD") == 0)
		return HTTP_RESPONSE_PAYLOAD_TYPE_NOT_PRESENT;
	if (strcmp(req->method, "CONNECT") == 0)
		return HTTP_RESPONSE_PAYLOAD_TYPE_ONLY_UNSUCCESSFUL;
	return HTTP_RESPONSE_PAYLOAD_TYPE_ALLOWED;
}

static void http_client_request_do_submit(struct http_client_request *req)
{
	struct http_client *client = req->client;
	struct http_client_host *host;
	const char *proxy_socket_path = client->set.proxy_socket_path;
	const struct http_url *proxy_url = client->set.proxy_url;
	bool have_proxy = (proxy_socket_path != NULL) || (proxy_url != NULL);
	const char *authority, *target;

	i_assert(req->state == HTTP_REQUEST_STATE_NEW);

	authority = http_url_create_authority(&req->origin_url);
	if (req->connect_tunnel) {
		/* connect requests require authority form for request target */
		target = authority;
	} else {
		/* absolute target url */
		target = t_strconcat
			(http_url_create_host(&req->origin_url), req->target, NULL);
	}

	/* determine what host to contact to submit this request */
	if (have_proxy) {
		if (req->origin_url.have_ssl && !client->set.no_ssl_tunnel &&
			!req->connect_tunnel) {
			req->host_url = &req->origin_url;           /* tunnel to origin server */
			req->ssl_tunnel = TRUE;
		} else if (proxy_socket_path != NULL) {
			req->host_socket = proxy_socket_path;       /* proxy on unix socket */
			req->host_url = NULL;
		} else {
			req->host_url = proxy_url;                  /* normal proxy server */
			req->host_socket = NULL;
		}
	} else {
		req->host_url = &req->origin_url;             /* origin server */
	}

	/* use submission date if no date is set explicitly */
	if (req->date == (time_t)-1)
		req->date = ioloop_time;
	
	/* prepare value for Host header */
	req->authority = p_strdup(req->pool, authority);

	/* debug label */
	req->label = p_strdup_printf(req->pool, "[%s %s]", req->method, target);

	/* update request target */
	if (req->connect_tunnel || have_proxy)
		req->target = p_strdup(req->pool, target);

	if (!have_proxy) {
		/* if we don't have a proxy, CONNECT requests are handled by creating
		   the requested connection directly */
		req->connect_direct = req->connect_tunnel;
		if (req->connect_direct)
			req->urgent = TRUE;
	}

	if (req->timeout_time.tv_sec == 0) {
		if (req->timeout_msecs > 0) {
			req->timeout_time = ioloop_timeval;
			timeval_add_msecs(&req->timeout_time, req->timeout_msecs);
		} else if (	client->set.request_absolute_timeout_msecs > 0) {
			req->timeout_time = ioloop_timeval;
			timeval_add_msecs(&req->timeout_time, client->set.request_absolute_timeout_msecs);
		}
	}

	host = http_client_host_get(req->client, req->host_url);
	req->state = HTTP_REQUEST_STATE_QUEUED;

	http_client_host_submit_request(host, req);
}

void http_client_request_submit(struct http_client_request *req)
{
	struct http_client *client = req->client;

	req->submit_time = ioloop_timeval;

	http_client_request_do_submit(req);
	http_client_request_debug(req, "Submitted");

	req->submitted = TRUE;
	DLLIST_PREPEND(&client->requests_list, req);
	client->requests_count++;
}

void
http_client_request_get_peer_addr(const struct http_client_request *req,
	struct http_client_peer_addr *addr)
{
	const char *host_socket = req->host_socket;
	const struct http_url *host_url = req->host_url;
	
	/* the IP address may be unassigned in the returned peer address, since
	   that is only available at this stage when the target URL has an
	   explicit IP address. */
	memset(addr, 0, sizeof(*addr));
	if (host_socket != NULL) {
		addr->type = HTTP_CLIENT_PEER_ADDR_UNIX;
		addr->a.un.path = host_socket;		
	} else if (req->connect_direct) {
		addr->type = HTTP_CLIENT_PEER_ADDR_RAW;
		if (host_url->have_host_ip)
			addr->a.tcp.ip = host_url->host_ip;
		addr->a.tcp.port =
			(host_url->have_port ? host_url->port : HTTPS_DEFAULT_PORT);
	} else if (host_url->have_ssl) {
		if (req->ssl_tunnel)
			addr->type = HTTP_CLIENT_PEER_ADDR_HTTPS_TUNNEL;
		else
			addr->type = HTTP_CLIENT_PEER_ADDR_HTTPS;
		if (host_url->have_host_ip)
			addr->a.tcp.ip = host_url->host_ip;
		addr->a.tcp.https_name = host_url->host_name;
 		addr->a.tcp.port =
			(host_url->have_port ? host_url->port : HTTPS_DEFAULT_PORT);
	} else {
		addr->type = HTTP_CLIENT_PEER_ADDR_HTTP;
		if (host_url->have_host_ip)
			addr->a.tcp.ip = host_url->host_ip;
		addr->a.tcp.port =
			(host_url->have_port ? host_url->port : HTTP_DEFAULT_PORT);
	}
}

static void
http_client_request_finish_payload_out(struct http_client_request *req)
{
	i_assert(req->conn != NULL);

	/* drop payload output stream */
	if (req->payload_output != NULL) {
		o_stream_unref(&req->payload_output);
		req->payload_output = NULL;
	}

	/* advance state only when request didn't get aborted in the mean time */
	if (req->state != HTTP_REQUEST_STATE_ABORTED) {
		i_assert(req->state == HTTP_REQUEST_STATE_PAYLOAD_OUT);

		/* we're now waiting for a response from the server */
		req->state = HTTP_REQUEST_STATE_WAITING;
		http_client_connection_start_request_timeout(req->conn);
	}

	/* release connection */
	req->conn->output_locked = FALSE;

	http_client_request_debug(req, "Finished sending%s payload",
		(req->state == HTTP_REQUEST_STATE_ABORTED ? " aborted" : ""));
}

static int
http_client_request_continue_payload(struct http_client_request **_req,
	const unsigned char *data, size_t size)
{
	struct ioloop *prev_ioloop = current_ioloop;
	struct http_client_request *req = *_req;
	struct http_client_connection *conn = req->conn;
	struct http_client *client = req->client;
	int ret;

	i_assert(req->state == HTTP_REQUEST_STATE_NEW ||
		req->state == HTTP_REQUEST_STATE_PAYLOAD_OUT);
	i_assert(req->payload_input == NULL);

	if (conn != NULL)
		http_client_connection_ref(conn);
	http_client_request_ref(req);
	req->payload_wait = TRUE;

	if (data == NULL) {
		req->payload_input = NULL;
		if (req->state == HTTP_REQUEST_STATE_PAYLOAD_OUT)
			http_client_request_finish_payload_out(req);
	} else { 
		req->payload_input = i_stream_create_from_data(data, size);
		i_stream_set_name(req->payload_input, "<HTTP request payload>");
	}
	req->payload_size = 0;
	req->payload_chunked = TRUE;

	if (req->state == HTTP_REQUEST_STATE_NEW)
		http_client_request_submit(req);

	/* Wait for payload data to be written */

	i_assert(client->ioloop == NULL);
	client->ioloop = io_loop_create();
	http_client_switch_ioloop(client);
	if (client->set.dns_client != NULL)
		dns_client_switch_ioloop(client->set.dns_client);

	while (req->state < HTTP_REQUEST_STATE_PAYLOAD_IN) {
		http_client_request_debug(req, "Waiting for request to finish");
		
		if (req->state == HTTP_REQUEST_STATE_PAYLOAD_OUT)
			o_stream_set_flush_pending(req->payload_output, TRUE);
		io_loop_run(client->ioloop);

		if (req->state == HTTP_REQUEST_STATE_PAYLOAD_OUT &&
			req->payload_input->eof) {
			i_stream_unref(&req->payload_input);
			req->payload_input = NULL;
			break;
		}
	}

	io_loop_set_current(prev_ioloop);
	http_client_switch_ioloop(client);
	if (client->set.dns_client != NULL)
		dns_client_switch_ioloop(client->set.dns_client);
	io_loop_set_current(client->ioloop);
	io_loop_destroy(&client->ioloop);

	switch (req->state) {
	case HTTP_REQUEST_STATE_PAYLOAD_IN:
	case HTTP_REQUEST_STATE_FINISHED:
		ret = 1;
		break;
	case HTTP_REQUEST_STATE_ABORTED:
		ret = -1;
		break;
	default:
		ret = 0;
		break;
	}

	req->payload_wait = FALSE;

	/* callback may have messed with our pointer,
	   so unref using local variable */	
	http_client_request_unref(&req);
	if (req == NULL)
		*_req = NULL;

	if (conn != NULL)
		http_client_connection_unref(&conn);

	/* Return status */
	return ret;
}

int http_client_request_send_payload(struct http_client_request **_req,
	const unsigned char *data, size_t size)
{
	i_assert(data != NULL);

	return http_client_request_continue_payload(_req, data, size);
}

int http_client_request_finish_payload(struct http_client_request **_req)
{
	return http_client_request_continue_payload(_req, NULL, 0);
}

static void http_client_request_payload_input(struct http_client_request *req)
{	
	struct http_client_connection *conn = req->conn;

	if (conn->io_req_payload != NULL)
		io_remove(&conn->io_req_payload);

	(void)http_client_connection_output(conn);
}

int http_client_request_send_more(struct http_client_request *req,
				  const char **error_r)
{
	struct http_client_connection *conn = req->conn;
	struct ostream *output = req->payload_output;
	off_t ret;

	i_assert(req->payload_input != NULL);
	i_assert(req->payload_output != NULL);

	if (conn->io_req_payload != NULL)
		io_remove(&conn->io_req_payload);

	/* chunked ostream needs to write to the parent stream's buffer */
	o_stream_set_max_buffer_size(output, IO_BLOCK_SIZE);
	ret = o_stream_send_istream(output, req->payload_input);
	o_stream_set_max_buffer_size(output, (size_t)-1);

	if (req->payload_input->stream_errno != 0) {
		/* the payload stream assigned to this request is broken,
		   fail this the request immediately */
		http_client_request_send_error(req,
			HTTP_CLIENT_REQUEST_ERROR_BROKEN_PAYLOAD,
			"Broken payload stream");

		/* we're in the middle of sending a request, so the connection
		   will also have to be aborted */
		errno = req->payload_input->stream_errno;
		*error_r = t_strdup_printf("read(%s) failed: %s",
					   i_stream_get_name(req->payload_input),
					   i_stream_get_error(req->payload_input));
		return -1;
	} else if (output->stream_errno != 0) {
		/* failed to send request */
		errno = output->stream_errno;
		*error_r = t_strdup_printf("write(%s) failed: %s",
					   o_stream_get_name(output),
					   o_stream_get_error(output));
		return -1;
	}
	i_assert(ret >= 0);

	if (i_stream_is_eof(req->payload_input)) {
		/* finished sending */
		if (!req->payload_chunked &&
		    req->payload_input->v_offset - req->payload_offset != req->payload_size) {
			*error_r = t_strdup_printf("BUG: stream '%s' input size changed: "
				"%"PRIuUOFF_T"-%"PRIuUOFF_T" != %"PRIuUOFF_T,
				i_stream_get_name(req->payload_input),
				req->payload_input->v_offset, req->payload_offset, req->payload_size);
			i_error("%s", *error_r); //FIXME: remove?
			return -1;
		}

		if (req->payload_wait) {
			/* this chunk of input is finished
			   (client needs to act; disable timeout) */
			conn->output_locked = TRUE;
			http_client_connection_stop_request_timeout(conn);
			if (req->client->ioloop != NULL)
				io_loop_stop(req->client->ioloop);
		} else {
			/* finished sending payload */
			http_client_request_finish_payload_out(req);
		}
	} else if (i_stream_get_data_size(req->payload_input) > 0) {
		/* output is blocking (server needs to act; enable timeout) */
		conn->output_locked = TRUE;
		http_client_connection_start_request_timeout(conn);
		o_stream_set_flush_pending(output, TRUE);
		http_client_request_debug(req, "Partially sent payload");
	} else {
		/* input is blocking (client needs to act; disable timeout) */
		conn->output_locked = TRUE;	
		http_client_connection_stop_request_timeout(conn);
		conn->io_req_payload = io_add_istream(req->payload_input,
			http_client_request_payload_input, req);
	}
	return 0;
}

static int http_client_request_send_real(struct http_client_request *req,
					 const char **error_r)
{
	const struct http_client_settings *set = &req->client->set;
	struct http_client_connection *conn = req->conn;
	struct ostream *output = conn->conn.output;
	string_t *rtext = t_str_new(256);
	struct const_iovec iov[3];
	int ret = 0;

	i_assert(!req->conn->output_locked);
	i_assert(req->payload_output == NULL);

	/* create request line */
	str_append(rtext, req->method);
	str_append(rtext, " ");
	str_append(rtext, req->target);
	str_append(rtext, " HTTP/1.1\r\n");

	/* create special headers implicitly if not set explicitly using
	   http_client_request_add_header() */
	if (!req->have_hdr_host) {
		str_append(rtext, "Host: ");
		str_append(rtext, req->authority);
		str_append(rtext, "\r\n");
	}
	if (!req->have_hdr_date) {
		str_append(rtext, "Date: ");
		str_append(rtext, http_date_create(req->date));
		str_append(rtext, "\r\n");
	}
	if (!req->have_hdr_authorization &&
		req->username != NULL && req->password != NULL) {
		struct http_auth_credentials auth_creds;

		http_auth_basic_credentials_init(&auth_creds,
			req->username, req->password);

		str_append(rtext, "Authorization: ");
		http_auth_create_credentials(rtext, &auth_creds);
		str_append(rtext, "\r\n");
	}
	if (http_client_request_to_proxy(req) &&
		set->proxy_username != NULL && set->proxy_password != NULL) {
		struct http_auth_credentials auth_creds;

		http_auth_basic_credentials_init(&auth_creds,
			set->proxy_username, set->proxy_password);

		str_append(rtext, "Proxy-Authorization: ");
		http_auth_create_credentials(rtext, &auth_creds);
		str_append(rtext, "\r\n");
	}
	if (!req->have_hdr_user_agent && req->client->set.user_agent != NULL) {
		str_printfa(rtext, "User-Agent: %s\r\n",
			    req->client->set.user_agent);
	}
	if (!req->have_hdr_expect && req->payload_sync) {
		str_append(rtext, "Expect: 100-continue\r\n");
	}
	if (req->payload_input != NULL) {
		if (req->payload_chunked) {
			// FIXME: can't do this for a HTTP/1.0 server
			if (!req->have_hdr_body_spec)
				str_append(rtext, "Transfer-Encoding: chunked\r\n");
			req->payload_output =
				http_transfer_chunked_ostream_create(output);
		} else {
			/* send Content-Length if we have specified a payload,
				 even if it's 0 bytes. */
			if (!req->have_hdr_body_spec) {
				str_printfa(rtext, "Content-Length: %"PRIuUOFF_T"\r\n",
					req->payload_size);
			}
			req->payload_output = output;
			o_stream_ref(output);
		}
	}
	if (!req->have_hdr_connection &&
		!http_client_request_to_proxy(req)) {
		/* https://tools.ietf.org/html/rfc2068
		     Section 19.7.1:

		   A client MUST NOT send the Keep-Alive connection token to a proxy
		   server as HTTP/1.0 proxy servers do not obey the rules of HTTP/1.1
		   for parsing the Connection header field.
		 */
		str_append(rtext, "Connection: Keep-Alive\r\n");
	}

	/* request line + implicit headers */
	iov[0].iov_base = str_data(rtext);
	iov[0].iov_len = str_len(rtext);	
	/* explicit headers */
	if (req->headers != NULL) {
		iov[1].iov_base = str_data(req->headers);
		iov[1].iov_len = str_len(req->headers);
	} else {
		iov[1].iov_base = "";
		iov[1].iov_len = 0;
	}
	/* end of header */
	iov[2].iov_base = "\r\n";
	iov[2].iov_len = 2;

	req->state = HTTP_REQUEST_STATE_PAYLOAD_OUT;
	req->sent_time = ioloop_timeval;
	o_stream_cork(output);
	if (o_stream_sendv(output, iov, N_ELEMENTS(iov)) < 0) {
		*error_r = t_strdup_printf("write(%s) failed: %s",
					   o_stream_get_name(output),
					   o_stream_get_error(output));
		ret = -1;
	} else {
		http_client_request_debug(req, "Sent header");

		if (req->payload_output != NULL) {
			if (!req->payload_sync) {
				if (http_client_request_send_more(req, error_r) < 0)
					ret = -1;
			} else {
				http_client_request_debug(req, "Waiting for 100-continue");
				conn->output_locked = TRUE;
			}
		} else {
			req->state = HTTP_REQUEST_STATE_WAITING;
			http_client_connection_start_request_timeout(req->conn);
			conn->output_locked = FALSE;
		}
		if (ret >= 0 && o_stream_flush(output) < 0) {
			*error_r = t_strdup_printf("flush(%s) failed: %s",
   	                   o_stream_get_name(output),
           	           o_stream_get_error(output));
			ret = -1;
		}
	}
	o_stream_uncork(output);
	return ret;
}

int http_client_request_send(struct http_client_request *req,
			     const char **error_r)
{
	char *errstr = NULL;
	int ret;

	T_BEGIN {
		ret = http_client_request_send_real(req, error_r);
		if (ret < 0)
			errstr = i_strdup(*error_r);
	} T_END;
	*error_r = t_strdup(errstr);
	i_free(errstr);
	return ret;
}

bool http_client_request_callback(struct http_client_request *req,
			     struct http_response *response)
{
	http_client_request_callback_t *callback = req->callback;
	unsigned int orig_attempts = req->attempts;

	req->state = HTTP_REQUEST_STATE_GOT_RESPONSE;

	req->callback = NULL;
	if (callback != NULL) {
		callback(response, req->context);
		if (req->attempts != orig_attempts) {
			/* retrying */
			req->callback = callback;
			http_client_request_resubmit(req);
			return FALSE;
		} else {
			/* release payload early (prevents server/client deadlock in proxy) */
			if (req->payload_input != NULL)
				i_stream_unref(&req->payload_input);
		}
	}
	return TRUE;
}

static void
http_client_request_send_error(struct http_client_request *req,
			       unsigned int status, const char *error)
{
	http_client_request_callback_t *callback;
	bool sending = (req->state == HTTP_REQUEST_STATE_PAYLOAD_OUT);

	req->state = HTTP_REQUEST_STATE_ABORTED;

	callback = req->callback;
	req->callback = NULL;
	if (callback != NULL) {
		struct http_response response;

		http_response_init(&response, status, error);
		(void)callback(&response, req->context);

		/* release payload early (prevents server/client deadlock in proxy) */
		if (!sending && req->payload_input != NULL)
			i_stream_unref(&req->payload_input);
	}
	if (req->payload_wait && req->client->ioloop != NULL)
		io_loop_stop(req->client->ioloop);
}

void http_client_request_error_delayed(struct http_client_request **_req)
{
	struct http_client_request *req = *_req;

	i_assert(req->state == HTTP_REQUEST_STATE_ABORTED);

	i_assert(req->delayed_error != NULL && req->delayed_error_status != 0);
	http_client_request_send_error(req, req->delayed_error_status,
				       req->delayed_error);
	if (req->queue != NULL)
		http_client_queue_drop_request(req->queue, req);
	http_client_request_unref(_req);
}

void http_client_request_error(struct http_client_request *req,
	unsigned int status, const char *error)
{
	if (req->state >= HTTP_REQUEST_STATE_FINISHED)
		return;
	req->state = HTTP_REQUEST_STATE_ABORTED;

	if (req->queue != NULL)
		http_client_queue_drop_request(req->queue, req);

	if (!req->submitted ||
		req->state == HTTP_REQUEST_STATE_GOT_RESPONSE) {
		/* we're still in http_client_request_submit() or in the callback
		   during a retry attempt. delay reporting the error, so the caller
		   doesn't have to handle immediate or nested callbacks. */
		i_assert(req->delayed_error == NULL);
		req->delayed_error = p_strdup(req->pool, error);
		req->delayed_error_status = status;
		http_client_delay_request_error(req->client, req);
	} else {
		http_client_request_send_error(req, status, error);
		http_client_request_unref(&req);
	}
}

void http_client_request_abort(struct http_client_request **_req)
{
	struct http_client_request *req = *_req;
	bool sending = (req->state == HTTP_REQUEST_STATE_PAYLOAD_OUT);

	if (req->state >= HTTP_REQUEST_STATE_FINISHED)
		return;

	req->callback = NULL;
	req->state = HTTP_REQUEST_STATE_ABORTED;

	/* release payload early (prevents server/client deadlock in proxy) */
	if (!sending && req->payload_input != NULL)
		i_stream_unref(&req->payload_input);

	if (req->queue != NULL)
		http_client_queue_drop_request(req->queue, req);
	if (req->payload_wait && req->client->ioloop != NULL)
		io_loop_stop(req->client->ioloop);
	http_client_request_unref(_req);
}

void http_client_request_finish(struct http_client_request **_req)
{
	struct http_client_request *req = *_req;

	if (req->state >= HTTP_REQUEST_STATE_FINISHED)
		return;

	http_client_request_debug(req, "Finished");

	req->callback = NULL;
	req->state = HTTP_REQUEST_STATE_FINISHED;

	if (req->queue != NULL)
		http_client_queue_drop_request(req->queue, req);
	if (req->payload_wait && req->client->ioloop != NULL)
		io_loop_stop(req->client->ioloop);
	http_client_request_unref(_req);
}

void http_client_request_redirect(struct http_client_request *req,
	unsigned int status, const char *location)
{
	struct http_url *url;
	const char *error, *target, *origin_url;

	i_assert(!req->payload_wait);

	/* parse URL */
	if (http_url_parse(location, NULL, 0,
			   pool_datastack_create(), &url, &error) < 0) {
		http_client_request_error(req, HTTP_CLIENT_REQUEST_ERROR_INVALID_REDIRECT,
			t_strdup_printf("Invalid redirect location: %s", error));
		return;
	}

	if (++req->redirects > req->client->set.max_redirects) {
		if (req->client->set.max_redirects > 0) {
			http_client_request_error(req,
				HTTP_CLIENT_REQUEST_ERROR_INVALID_REDIRECT,
				t_strdup_printf("Redirected more than %d times",
					req->client->set.max_redirects));
		} else {
			http_client_request_error(req,
				HTTP_CLIENT_REQUEST_ERROR_INVALID_REDIRECT,
					"Redirect refused");
		}
		return;
	}

	/* rewind payload stream */
	if (req->payload_input != NULL && req->payload_size > 0 && status != 303) {
		if (req->payload_input->v_offset != req->payload_offset &&
			!req->payload_input->seekable) {
			http_client_request_error(req,
				HTTP_CLIENT_REQUEST_ERROR_ABORTED,
				"Redirect failed: Cannot resend payload; stream is not seekable");
			return;
		} else {
			i_stream_seek(req->payload_input, req->payload_offset);
		}
	}

	/* drop payload output stream from previous attempt */
	if (req->payload_output != NULL)
		o_stream_unref(&req->payload_output);

	target = http_url_create_target(url);

	http_url_copy(req->pool, &req->origin_url, url);
	req->target = p_strdup(req->pool, target);
	
	req->host = NULL;
	req->conn = NULL;

	origin_url = http_url_create(&req->origin_url);

	http_client_request_debug(req, "Redirecting to %s%s",
		origin_url, target);

	req->label = p_strdup_printf(req->pool, "[%s %s%s]",
		req->method, origin_url, req->target);

	/* RFC 7231, Section 6.4.4:
	
	   -> A 303 `See Other' redirect status response is handled a bit differently.
	   Basically, the response content is located elsewhere, but the original
	   (POST) request is handled already.
	 */
	if (status == 303 && strcasecmp(req->method, "HEAD") != 0 &&
		strcasecmp(req->method, "GET") != 0) {
		// FIXME: should we provide the means to skip this step? The original
		// request was already handled at this point.
		req->method = p_strdup(req->pool, "GET");

		/* drop payload */
		if (req->payload_input != NULL)
			i_stream_unref(&req->payload_input);
		req->payload_size = 0;
		req->payload_offset = 0;
	}

	/* resubmit */
	req->state = HTTP_REQUEST_STATE_NEW;
	http_client_request_do_submit(req);
}

void http_client_request_resubmit(struct http_client_request *req)
{
	i_assert(!req->payload_wait);

	http_client_request_debug(req, "Resubmitting request");

	/* rewind payload stream */
	if (req->payload_input != NULL && req->payload_size > 0) {
		if (req->payload_input->v_offset != req->payload_offset &&
			!req->payload_input->seekable) {
			http_client_request_error(req,
				HTTP_CLIENT_REQUEST_ERROR_ABORTED,
				"Resubmission failed: Cannot resend payload; stream is not seekable");
			return;
		} else {
			i_stream_seek(req->payload_input, req->payload_offset);
		}
	}

	/* rewind payload stream */
	if (req->payload_input != NULL && req->payload_size > 0) {
		if (req->payload_input->v_offset != req->payload_offset &&
			!req->payload_input->seekable) {
			http_client_request_error(req,
				HTTP_CLIENT_REQUEST_ERROR_ABORTED,
				"Resubmission failed: Cannot resend payload; stream is not seekable");
			return;
		} else {
			i_stream_seek(req->payload_input, req->payload_offset);
		}
	}

	/* drop payload output stream from previous attempt */
	if (req->payload_output != NULL)
		o_stream_unref(&req->payload_output);

	req->conn = NULL;
	req->peer = NULL;
	req->state = HTTP_REQUEST_STATE_QUEUED;
	http_client_host_submit_request(req->host, req);
}

void http_client_request_retry(struct http_client_request *req,
	unsigned int status, const char *error)
{
	if (!http_client_request_try_retry(req))
		http_client_request_error(req, status, error);
}

bool http_client_request_try_retry(struct http_client_request *req)
{
	/* don't ever retry if we're sending data in small blocks via
	   http_client_request_send_payload() and we're not waiting for a
	   100 continue (there's no way to rewind the payload for a retry)
	 */
	if (req->payload_wait &&
		(!req->payload_sync || req->conn->payload_continue))
		return FALSE;
	/* limit the number of attempts for each request */
	if (req->attempts+1 >= req->client->set.max_attempts)
		return FALSE;
	req->attempts++;

	http_client_request_debug(req, "Retrying (attempts=%d)", req->attempts);
	if (req->callback != NULL)
		http_client_request_resubmit(req);
	return TRUE;
}

void http_client_request_set_destroy_callback(struct http_client_request *req,
					      void (*callback)(void *),
					      void *context)
{
	req->destroy_callback = callback;
	req->destroy_context = context;
}

void http_client_request_start_tunnel(struct http_client_request *req,
	struct http_client_tunnel *tunnel)
{
	i_assert(req->state == HTTP_REQUEST_STATE_GOT_RESPONSE);

	http_client_connection_start_tunnel(&req->conn, tunnel);
}
