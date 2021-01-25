/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "array.h"
#include "str.h"
#include "hostpid.h"
#include "ioloop.h"
#include "istream.h"
#include "istream-timeout.h"
#include "ostream.h"
#include "connection.h"
#include "iostream-rawlog.h"
#include "iostream-ssl.h"
#include "master-service.h"
#include "master-service-ssl.h"
#include "http-date.h"
#include "http-url.h"
#include "http-request-parser.h"

#include "http-server-private.h"

static void
http_server_connection_disconnect(struct http_server_connection *conn,
				  const char *reason);

static bool
http_server_connection_unref_is_closed(struct http_server_connection *conn);

/*
 * Logging
 */

static inline void
http_server_connection_client_error(struct http_server_connection *conn,
				    const char *format, ...) ATTR_FORMAT(2, 3);

static inline void
http_server_connection_client_error(struct http_server_connection *conn,
				    const char *format, ...)
{
	va_list args;

	va_start(args, format);
	e_info(conn->event, "%s", t_strdup_vprintf(format, args));
	va_end(args);
}

/*
 * Connection
 */

static void http_server_connection_input(struct connection *_conn);

static void
http_server_connection_update_stats(struct http_server_connection *conn)
{
	if (conn->conn.input != NULL)
		conn->stats.input = conn->conn.input->v_offset;
	if (conn->conn.output != NULL)
		conn->stats.output = conn->conn.output->offset;
}

const struct http_server_stats *
http_server_connection_get_stats(struct http_server_connection *conn)
{
	http_server_connection_update_stats(conn);
	return &conn->stats;
}

void http_server_connection_input_set_pending(
	struct http_server_connection *conn)
{
	i_stream_set_input_pending(conn->conn.input, TRUE);
}

void http_server_connection_input_halt(struct http_server_connection *conn)
{
	connection_input_halt(&conn->conn);
}

void http_server_connection_input_resume(struct http_server_connection *conn)
{
	if (conn->closed || conn->input_broken || conn->close_indicated ||
	    conn->incoming_payload != NULL) {
		/* Connection not usable */
		return;
	}

	if (conn->in_req_callback) {
		struct http_server_request *req = conn->request_queue_tail;

		/* Currently running request callback for this connection. Only
		   handle discarded request payload. */
		if (req == NULL ||
		    req->state != HTTP_SERVER_REQUEST_STATE_SUBMITTED_RESPONSE)
			return;
		if (!http_server_connection_pending_payload(conn))
			return;
	}

	connection_input_resume(&conn->conn);
}

static void
http_server_connection_idle_timeout(struct http_server_connection *conn)
{
	http_server_connection_client_error(
		conn, "Disconnected for inactivity");
	http_server_connection_close(&conn, "Disconnected for inactivity");
}

void http_server_connection_start_idle_timeout(
	struct http_server_connection *conn)
{
	unsigned int timeout_msecs =
		conn->server->set.max_client_idle_time_msecs;

	if (conn->to_idle == NULL && timeout_msecs > 0) {
		conn->to_idle = timeout_add(timeout_msecs,
					    http_server_connection_idle_timeout,
					    conn);
	}
}

void http_server_connection_reset_idle_timeout(
	struct http_server_connection *conn)
{
	if (conn->to_idle != NULL)
		timeout_reset(conn->to_idle);
}

void http_server_connection_stop_idle_timeout(
	struct http_server_connection *conn)
{
	timeout_remove(&conn->to_idle);
}

bool http_server_connection_shut_down(struct http_server_connection *conn)
{
	if (conn->request_queue_head == NULL ||
	    conn->request_queue_head->state == HTTP_SERVER_REQUEST_STATE_NEW) {
		http_server_connection_close(&conn, "Server shutting down");
		return TRUE;
	}
	return FALSE;
}

static void http_server_connection_ready(struct http_server_connection *conn)
{
	const struct http_server_settings *set = &conn->server->set;
	struct http_url base_url;
	struct stat st;

	if (conn->server->set.rawlog_dir != NULL &&
	    stat(conn->server->set.rawlog_dir, &st) == 0) {
		iostream_rawlog_create(conn->server->set.rawlog_dir,
				       &conn->conn.input, &conn->conn.output);
	}

	i_zero(&base_url);
	if (set->default_host != NULL)
		base_url.host.name = set->default_host;
	else
		base_url.host.name = my_hostname;
	base_url.have_ssl = conn->ssl;

	conn->http_parser = http_request_parser_init(
		conn->conn.input, &base_url, &conn->server->set.request_limits,
		HTTP_REQUEST_PARSE_FLAG_STRICT);
	o_stream_set_finish_via_child(conn->conn.output, FALSE);
	o_stream_set_flush_callback(conn->conn.output,
				    http_server_connection_output, conn);
}

static void http_server_connection_destroy(struct connection *_conn)
{
	struct http_server_connection *conn =
		(struct http_server_connection *)_conn;

	http_server_connection_disconnect(conn, NULL);
	http_server_connection_unref(&conn);
}

static void http_server_payload_destroyed(struct http_server_request *req)
{
	struct http_server_connection *conn = req->conn;
	int stream_errno;

	i_assert(conn != NULL);
	i_assert(conn->request_queue_tail == req ||
		 req->state >= HTTP_SERVER_REQUEST_STATE_FINISHED);
	i_assert(conn->conn.io == NULL);

	e_debug(conn->event, "Request payload stream destroyed");

	/* Caller is allowed to change the socket fd to blocking while reading
	   the payload. make sure here that it's switched back. */
	net_set_nonblock(conn->conn.fd_in, TRUE);

	stream_errno = conn->incoming_payload->stream_errno;
	conn->incoming_payload = NULL;

	if (conn->payload_handler != NULL)
		http_server_payload_handler_destroy(&conn->payload_handler);

	/* Handle errors in transfer stream */
	if (req->response == NULL && stream_errno != 0 &&
	    conn->conn.input->stream_errno == 0) {
		switch (stream_errno) {
		case EMSGSIZE:
			conn->input_broken = TRUE;
			http_server_connection_client_error(
				conn, "Client sent excessively large request");
			http_server_request_fail_close(req, 413,
						       "Payload Too Large");
			return;
		case EIO:
			conn->input_broken = TRUE;
			http_server_connection_client_error(
				conn, "Client sent invalid request payload");
			http_server_request_fail_close(req, 400,
						       "Bad Request");
			return;
		default:
			break;
		}
	}

	/* Resource stopped reading payload; update state */
	switch (req->state) {
	case HTTP_SERVER_REQUEST_STATE_QUEUED:
	case HTTP_SERVER_REQUEST_STATE_PAYLOAD_IN:
		/* Finished reading request */
		req->state = HTTP_SERVER_REQUEST_STATE_PROCESSING;
		http_server_connection_stop_idle_timeout(conn);
		if (req->response != NULL && req->response->submitted)
			http_server_request_submit_response(req);
		break;
	case HTTP_SERVER_REQUEST_STATE_PROCESSING:
		/* No response submitted yet */
		break;
	case HTTP_SERVER_REQUEST_STATE_SUBMITTED_RESPONSE:
		/* Response submitted, but not all payload is necessarily read
		 */
		if (http_server_request_is_complete(req))
			http_server_request_ready_to_respond(req);
		break;
	case HTTP_SERVER_REQUEST_STATE_READY_TO_RESPOND:
	case HTTP_SERVER_REQUEST_STATE_FINISHED:
	case HTTP_SERVER_REQUEST_STATE_ABORTED:
		/* Nothing to do */
		break;
	default:
		i_unreached();
	}

	/* Input stream may have pending input. */
	http_server_connection_input_resume(conn);
	http_server_connection_input_set_pending(conn);
}

static bool
http_server_connection_handle_request(struct http_server_connection *conn,
				      struct http_server_request *req)
{
	const struct http_server_settings *set = &conn->server->set;
	unsigned int old_refcount;
	struct istream *payload;

	i_assert(!conn->in_req_callback);
	i_assert(conn->incoming_payload == NULL);

	if (req->req.version_major != 1) {
		http_server_request_fail(req, 505,
					 "HTTP Version Not Supported");
		return TRUE;
	}

	req->state = HTTP_SERVER_REQUEST_STATE_QUEUED;

	if (req->req.payload != NULL) {
		/* Wrap the stream to capture the destroy event without
		   destroying the actual payload stream. */
		conn->incoming_payload = req->req.payload =
			i_stream_create_timeout(
				req->req.payload,
				set->max_client_idle_time_msecs);
		/* We've received the request itself, and we can't reset the
		   timeout during the payload reading. */
		http_server_connection_stop_idle_timeout(conn);
	} else {
		conn->incoming_payload = req->req.payload =
			i_stream_create_from_data("", 0);
	}
	i_stream_add_destroy_callback(req->req.payload,
				      http_server_payload_destroyed, req);
	/* The callback may add its own I/O, so we need to remove our one before
	   calling it. */
	http_server_connection_input_halt(conn);

	old_refcount = req->refcount;
	conn->in_req_callback = TRUE;
	T_BEGIN {
		http_server_request_callback(req);
	} T_END;
	if (conn->closed) {
		/* The callback managed to get this connection destroyed/closed
		 */
		return FALSE;
	}
	conn->in_req_callback = FALSE;
	req->callback_refcount = req->refcount - old_refcount;

	if (req->req.payload != NULL) {
		/* Send 100 Continue when appropriate */
		if (req->req.expect_100_continue && !req->payload_halted &&
		    req->response == NULL) {
			http_server_connection_output_trigger(conn);
		}

		/* Delegate payload handling to request handler */
		if (req->state < HTTP_SERVER_REQUEST_STATE_PAYLOAD_IN)
			req->state = HTTP_SERVER_REQUEST_STATE_PAYLOAD_IN;
		payload = req->req.payload;
		req->req.payload = NULL;
		i_stream_unref(&payload);
	}

	if (req->state < HTTP_SERVER_REQUEST_STATE_PROCESSING &&
	    (conn->incoming_payload == NULL ||
	     !i_stream_have_bytes_left(conn->incoming_payload))) {
		/* Finished reading request */
		req->state = HTTP_SERVER_REQUEST_STATE_PROCESSING;
		if (req->response != NULL && req->response->submitted)
			http_server_request_submit_response(req);
	}

	i_assert(conn->incoming_payload != NULL || req->callback_refcount > 0 ||
		 (req->response != NULL && req->response->submitted));

	if (conn->incoming_payload == NULL) {
		http_server_connection_input_resume(conn);
		http_server_connection_input_set_pending(conn);
		return TRUE;
	}

	/* Request payload is still being uploaded by the client */
	return FALSE;
}

static int
http_server_connection_ssl_init(struct http_server_connection *conn)
{
	struct http_server *server = conn->server;
	const char *error;
	int ret;

	if (http_server_init_ssl_ctx(server, &error) < 0) {
		e_error(conn->event, "Couldn't initialize SSL: %s", error);
		return -1;
	}

	e_debug(conn->event, "Starting SSL handshake");

	http_server_connection_input_halt(conn);
	if (server->ssl_ctx == NULL) {
		ret = master_service_ssl_init(master_service,
					      &conn->conn.input,
					      &conn->conn.output,
					      &conn->ssl_iostream, &error);
	} else {
		ret = io_stream_create_ssl_server(server->ssl_ctx,
						  server->set.ssl,
						  &conn->conn.input,
						  &conn->conn.output,
						  &conn->ssl_iostream, &error);
	}
	if (ret < 0) {
		e_error(conn->event,
			"Couldn't initialize SSL server for %s: %s",
			conn->conn.name, error);
		return -1;
	}
	http_server_connection_input_resume(conn);

	if (ssl_iostream_handshake(conn->ssl_iostream) < 0) {
		e_error(conn->event, "SSL handshake failed: %s",
			ssl_iostream_get_last_error(conn->ssl_iostream));
		return -1;
	}

	http_server_connection_ready(conn);
	return 0;
}

static bool
http_server_connection_pipeline_is_full(struct http_server_connection *conn)
{
	return ((conn->request_queue_count >=
		 conn->server->set.max_pipelined_requests) ||
		conn->server->shutting_down);
}

static void
http_server_connection_pipeline_handle_full(struct http_server_connection *conn)
{
	if (conn->server->shutting_down) {
		e_debug(conn->event, "Pipeline full "
			"(%u requests pending; server shutting down)",
			conn->request_queue_count);
	} else {
		e_debug(conn->event, "Pipeline full "
			"(%u requests pending; %u maximum)",
			conn->request_queue_count,
			conn->server->set.max_pipelined_requests);
	}
	http_server_connection_input_halt(conn);
}

static bool
http_server_connection_check_input(struct http_server_connection *conn)
{
	struct istream *input = conn->conn.input;
	int stream_errno;

	if (input == NULL)
		return FALSE;
	stream_errno = input->stream_errno;

	if (input->eof || stream_errno != 0) {
		/* Connection input broken; output may still be intact */
		if (stream_errno != 0 && stream_errno != EPIPE &&
		    stream_errno != ECONNRESET) {
			http_server_connection_client_error(
				conn, "Connection lost: read(%s) failed: %s",
				i_stream_get_name(input),
				i_stream_get_error(input));
			http_server_connection_close(&conn, "Read failure");
		} else {
			e_debug(conn->event, "Connection lost: "
				"Remote disconnected");

			if (conn->request_queue_head == NULL) {
				/* No pending requests; close */
				http_server_connection_close(
					&conn, "Remote closed connection");
			} else if (conn->request_queue_head->state <
				   HTTP_SERVER_REQUEST_STATE_SUBMITTED_RESPONSE) {
				/* Unfinished request; close */
				http_server_connection_close(&conn,
					"Remote closed connection unexpectedly");
			} else {
				/* A request is still processing; only drop
				   input io for now. The other end may only have
				   shutdown one direction */
				conn->input_broken = TRUE;
				http_server_connection_input_halt(conn);
			}
		}
		return FALSE;
	}
	return TRUE;
}

static bool
http_server_connection_finish_request(struct http_server_connection *conn)
{
	struct http_server_request *req;
	enum http_request_parse_error error_code;
	const char *error;
	int ret;

	req = conn->request_queue_tail;
	if (req != NULL &&
	    req->state == HTTP_SERVER_REQUEST_STATE_SUBMITTED_RESPONSE) {

		e_debug(conn->event, "Finish receiving request");

		ret = http_request_parse_finish_payload(conn->http_parser,
							&error_code, &error);
		if (ret <= 0 && !http_server_connection_check_input(conn))
			return FALSE;
		if (ret < 0) {
			http_server_connection_ref(conn);

			http_server_connection_client_error(
				conn, "Client sent invalid request: %s", error);

			switch (error_code) {
			case HTTP_REQUEST_PARSE_ERROR_PAYLOAD_TOO_LARGE:
				conn->input_broken = TRUE;
				http_server_request_fail_close(
					req, 413, "Payload Too Large");
				break;
			case HTTP_REQUEST_PARSE_ERROR_BROKEN_REQUEST:
				conn->input_broken = TRUE;
				http_server_request_fail_close(
					req, 400, "Bad request");
				break;
			default:
				i_unreached();
			}

			if (http_server_connection_unref_is_closed(conn)) {
				/* Connection got closed */
				return FALSE;
			}

			if (conn->input_broken || conn->close_indicated)
				http_server_connection_input_halt(conn);
			return FALSE;
		}
		if (ret == 0)
			return FALSE;
		http_server_request_ready_to_respond(req);
	}

	return TRUE;
}

static void http_server_connection_input(struct connection *_conn)
{
	struct http_server_connection *conn =
		(struct http_server_connection *)_conn;
	struct http_server_request *req;
	enum http_request_parse_error error_code;
	const char *error;
	bool cont;
	int ret;

	if (conn->server->shutting_down) {
		if (!http_server_connection_shut_down(conn))
			http_server_connection_pipeline_handle_full(conn);
		return;
	}

	i_assert(!conn->input_broken && conn->incoming_payload == NULL);
	i_assert(!conn->close_indicated);

	http_server_connection_reset_idle_timeout(conn);

	if (conn->ssl && conn->ssl_iostream == NULL) {
		if (http_server_connection_ssl_init(conn) < 0) {
			/* SSL failed */
			http_server_connection_close(
				&conn, "SSL Initialization failed");
			return;
		}
	}

	/* Finish up pending request */
	if (!http_server_connection_finish_request(conn))
		return;

	/* Stop handling input here when running ioloop from within request
	   callback; we cannot read the next request, since that could mean
	   recursing request callbacks. */
	if (conn->in_req_callback) {
		http_server_connection_input_halt(conn);
		return;
	}

	/* Create request object if none was created already */
	if (conn->request_queue_tail != NULL &&
	    conn->request_queue_tail->state == HTTP_SERVER_REQUEST_STATE_NEW) {
		if (conn->request_queue_count >
		    conn->server->set.max_pipelined_requests) {
			/* Pipeline full */
			http_server_connection_pipeline_handle_full(conn);
			return;
		}
		/* Continue last unfinished request */
		req = conn->request_queue_tail;
	} else {
		if (conn->request_queue_count >=
		    conn->server->set.max_pipelined_requests) {
			/* Pipeline full */
			http_server_connection_pipeline_handle_full(conn);
			return;
		}
		/* Start new request */
		req = http_server_request_new(conn);
	}

	/* Parse requests */
	ret = 1;
	while (!conn->close_indicated && ret != 0) {
		http_server_connection_ref(conn);
		while ((ret = http_request_parse_next(
			conn->http_parser, req->pool, &req->req,
			&error_code, &error)) > 0) {
			conn->stats.request_count++;
			http_server_request_update_event(req);
			e_debug(conn->event, "Received new request %s "
				"(%u requests pending; %u maximum)",
				http_server_request_label(req),
				conn->request_queue_count,
				conn->server->set.max_pipelined_requests);

			http_server_request_immune_ref(req);
			T_BEGIN {
				cont = http_server_connection_handle_request(conn, req);
			} T_END;
			if (!cont) {
				/* Connection closed or request body not read
				   yet. The request may be destroyed now. */
				http_server_request_immune_unref(&req);
				http_server_connection_unref(&conn);
				return;
			}
			if (req->req.connection_close)
				conn->close_indicated = TRUE;
			http_server_request_immune_unref(&req);

			if (conn->closed) {
				/* Connection got closed in destroy callback */
				break;
			}

			if (conn->close_indicated) {
				/* Client indicated it will close after this
				   request; stop trying to read more. */
				break;
			}

			/* Finish up pending request if possible */
			if (!http_server_connection_finish_request(conn)) {
				http_server_connection_unref(&conn);
				return;
			}

			if (http_server_connection_pipeline_is_full(conn)) {
				/* Pipeline full */
				http_server_connection_pipeline_handle_full(conn);
				http_server_connection_unref(&conn);
				return;
			}

			/* Start new request */
			req = http_server_request_new(conn);
		}

		if (http_server_connection_unref_is_closed(conn)) {
			/* Connection got closed */
			return;
		}

		if (ret <= 0 && !http_server_connection_check_input(conn))
			return;

		if (ret < 0) {
			http_server_connection_ref(conn);

			http_server_connection_client_error(
				conn, "Client sent invalid request: %s", error);

			switch (error_code) {
			case HTTP_REQUEST_PARSE_ERROR_BROKEN_REQUEST:
				conn->input_broken = TRUE;
				/* fall through */
			case HTTP_REQUEST_PARSE_ERROR_BAD_REQUEST:
				http_server_request_fail(
					req, 400, "Bad Request");
				break;
			case HTTP_REQUEST_PARSE_ERROR_METHOD_TOO_LONG:
				conn->input_broken = TRUE;
				/* fall through */
			case HTTP_REQUEST_PARSE_ERROR_NOT_IMPLEMENTED:
				http_server_request_fail(
					req, 501, "Not Implemented");
				break;
			case HTTP_REQUEST_PARSE_ERROR_TARGET_TOO_LONG:
				conn->input_broken = TRUE;
				http_server_request_fail_close(
					req, 414, "URI Too Long");
				break;
			case HTTP_REQUEST_PARSE_ERROR_EXPECTATION_FAILED:
				http_server_request_fail(
					req, 417, "Expectation Failed");
				break;
			case HTTP_REQUEST_PARSE_ERROR_PAYLOAD_TOO_LARGE:
				conn->input_broken = TRUE;
				http_server_request_fail_close(
					req, 413, "Payload Too Large");
				break;
			default:
				i_unreached();
			}

			if (http_server_connection_unref_is_closed(conn)) {
				/* Connection got closed */
				return;
			}
		}

		if (conn->input_broken || conn->close_indicated) {
			http_server_connection_input_halt(conn);
			return;
		}
	}
}

void http_server_connection_handle_output_error(
	struct http_server_connection *conn)
{
	struct ostream *output = conn->conn.output;

	if (conn->closed)
		return;

	if (output->stream_errno != EPIPE &&
	    output->stream_errno != ECONNRESET) {
		e_error(conn->event, "Connection lost: write(%s) failed: %s",
			o_stream_get_name(output),
			o_stream_get_error(output));
		http_server_connection_close(
			&conn, "Write failure");
	} else {
		e_debug(conn->event, "Connection lost: Remote disconnected");
		http_server_connection_close(
			&conn, "Remote closed connection unexpectedly");
	}
}

enum _output_result {
	/* Error */
	_OUTPUT_ERROR = -1,
	/* Output blocked */
	_OUTPUT_BLOCKED = 0,
	/* Successful, but no more responses are ready to be sent */
	_OUTPUT_FINISHED = 1,
	/* Successful and more responses can be sent */
	_OUTPUT_AVAILABLE = 2,
};

static enum _output_result
http_server_connection_next_response(struct http_server_connection *conn)
{
	struct http_server_request *req;
	int ret;

	if (conn->output_locked)
		return _OUTPUT_FINISHED;

	req = conn->request_queue_head;
	if (req == NULL || req->state == HTTP_SERVER_REQUEST_STATE_NEW) {
		/* No requests pending */
		e_debug(conn->event, "No more requests pending");
		http_server_connection_start_idle_timeout(conn);
		return _OUTPUT_FINISHED;
	}
	if (req->state < HTTP_SERVER_REQUEST_STATE_READY_TO_RESPOND) {
		if (req->state == HTTP_SERVER_REQUEST_STATE_PROCESSING) {
			/* Server is causing idle time */
			e_debug(conn->event, "Not ready to respond: "
				"Server is processing");
			http_server_connection_stop_idle_timeout(conn);
		} else {
			/* Client is causing idle time */
			e_debug(conn->event, "Not ready to respond: "
				"Waiting for client");
			http_server_connection_start_idle_timeout(conn);
		}

		/* send 100 Continue if appropriate */
		if (req->state >= HTTP_SERVER_REQUEST_STATE_QUEUED &&
		    conn->incoming_payload != NULL &&
		    req->response == NULL && req->req.version_minor >= 1 &&
		    req->req.expect_100_continue && !req->payload_halted &&
		    !req->sent_100_continue) {
			static const char *response =
				"HTTP/1.1 100 Continue\r\n\r\n";
			struct ostream *output = conn->conn.output;

			if (o_stream_send(output, response,
					  strlen(response)) < 0) {
				http_server_connection_handle_output_error(conn);
				return _OUTPUT_ERROR;
			}

			e_debug(conn->event, "Sent 100 Continue");
			req->sent_100_continue = TRUE;
		}
		return _OUTPUT_FINISHED;
	}

	i_assert(req->state == HTTP_SERVER_REQUEST_STATE_READY_TO_RESPOND &&
		 req->response != NULL);

	e_debug(conn->event, "Sending response");
	http_server_connection_start_idle_timeout(conn);

	http_server_request_immune_ref(req);
	ret = http_server_response_send(req->response);
	http_server_request_immune_unref(&req);

	if (ret < 0)
		return _OUTPUT_ERROR;

	http_server_connection_reset_idle_timeout(conn);
	if (ret == 0)
		return _OUTPUT_BLOCKED;
	if (conn->output_locked)
		return _OUTPUT_FINISHED;
	return _OUTPUT_AVAILABLE;
}

static int
http_server_connection_send_responses(struct http_server_connection *conn)
{
	enum _output_result ores = _OUTPUT_AVAILABLE;

	http_server_connection_ref(conn);

	/* Send more responses until no more responses remain, the output
	   blocks again, or the connection is closed */
	while (!conn->closed && ores == _OUTPUT_AVAILABLE)
		ores = http_server_connection_next_response(conn);

	if (http_server_connection_unref_is_closed(conn) ||
	    ores == _OUTPUT_ERROR)
		return -1;

	/* Accept more requests if possible */
	if (conn->incoming_payload == NULL &&
	    (conn->request_queue_count <
	     conn->server->set.max_pipelined_requests) &&
	    !conn->server->shutting_down)
		http_server_connection_input_resume(conn);

	switch (ores) {
	case _OUTPUT_ERROR:
	case _OUTPUT_AVAILABLE:
		break;
	case _OUTPUT_BLOCKED:
		return 0;
	case _OUTPUT_FINISHED:
		return 1;
	}
	i_unreached();
}

int http_server_connection_flush(struct http_server_connection *conn)
{
	struct ostream *output = conn->conn.output;
	int ret;

	if ((ret = o_stream_flush(output)) <= 0) {
		if (ret < 0)
			http_server_connection_handle_output_error(conn);
		return ret;
	}

	http_server_connection_reset_idle_timeout(conn);
	return 0;
}

int http_server_connection_output(struct http_server_connection *conn)
{
	bool pipeline_was_full =
		http_server_connection_pipeline_is_full(conn);
	int ret = 1;

	if (http_server_connection_flush(conn) < 0)
		return -1;

	if (!conn->output_locked) {
		ret = http_server_connection_send_responses(conn);
		if (ret < 0)
			return -1;
	} else if (conn->request_queue_head != NULL) {
		struct http_server_request *req = conn->request_queue_head;
		struct http_server_response *resp = req->response;

		i_assert(resp != NULL);

		http_server_connection_ref(conn);

		http_server_request_immune_ref(req);
		ret = http_server_response_send_more(resp);
		http_server_request_immune_unref(&req);

		if (http_server_connection_unref_is_closed(conn) || ret < 0)
			return -1;

		if (!conn->output_locked) {
			/* Room for more responses */
			ret = http_server_connection_send_responses(conn);
			if (ret < 0)
				return -1;
		} else if (conn->io_resp_payload != NULL) {
			/* Server is causing idle time */
			e_debug(conn->event, "Not ready to continue response: "
				"Server is producing response");
			http_server_connection_stop_idle_timeout(conn);
		} else {
			/* Client is causing idle time */
			e_debug(conn->event, "Not ready to continue response: "
				"Waiting for client");
			http_server_connection_start_idle_timeout(conn);
		}
	}

	if (conn->server->shutting_down &&
	    http_server_connection_shut_down(conn))
		return 1;

	if (!http_server_connection_pipeline_is_full(conn)) {
		http_server_connection_input_resume(conn);
		if (pipeline_was_full && conn->conn.io != NULL)
			http_server_connection_input_set_pending(conn);
	}

	return ret;
}

void http_server_connection_output_trigger(struct http_server_connection *conn)
{
	if (conn->conn.output == NULL)
		return;
	o_stream_set_flush_pending(conn->conn.output, TRUE);
}

void http_server_connection_output_halt(struct http_server_connection *conn)
{
	conn->output_halted = TRUE;

	if (conn->conn.output == NULL)
		return;

	o_stream_unset_flush_callback(conn->conn.output);
}

void http_server_connection_output_resume(struct http_server_connection *conn)
{
	if (conn->output_halted) {
		conn->output_halted = FALSE;
		o_stream_set_flush_callback(conn->conn.output,
					    http_server_connection_output, conn);
	}
}

bool http_server_connection_pending_payload(
	struct http_server_connection *conn)
{
	return http_request_parser_pending_payload(conn->http_parser);
}

static struct connection_settings http_server_connection_set = {
	.input_max_size = SIZE_MAX,
	.output_max_size = SIZE_MAX,
	.client = FALSE,
	.log_connection_id = TRUE,
};

static const struct connection_vfuncs http_server_connection_vfuncs = {
	.destroy = http_server_connection_destroy,
	.input = http_server_connection_input
};

struct connection_list *http_server_connection_list_init(void)
{
	return connection_list_init(&http_server_connection_set,
				    &http_server_connection_vfuncs);
}

struct http_server_connection *
http_server_connection_create(struct http_server *server,
			      int fd_in, int fd_out, bool ssl,
			      const struct http_server_callbacks *callbacks,
			      void *context)
{
	const struct http_server_settings *set = &server->set;
	struct http_server_connection *conn;
	struct event *conn_event;

	i_assert(!server->shutting_down);

	conn = i_new(struct http_server_connection, 1);
	conn->refcount = 1;
	conn->server = server;
	conn->ioloop = current_ioloop;
	conn->ssl = ssl;
	conn->callbacks = callbacks;
	conn->context = context;

	net_set_nonblock(fd_in, TRUE);
	if (fd_in != fd_out)
		net_set_nonblock(fd_out, TRUE);
	(void)net_set_tcp_nodelay(fd_out, TRUE);

	if (set->socket_send_buffer_size > 0 &&
	    net_set_send_buffer_size(fd_out,
				     set->socket_send_buffer_size) < 0) {
		e_error(conn->event,
			"net_set_send_buffer_size(%zu) failed: %m",
			set->socket_send_buffer_size);
	}
	if (set->socket_recv_buffer_size > 0 &&
	    net_set_recv_buffer_size(fd_in,
				     set->socket_recv_buffer_size) < 0) {
		e_error(conn->event,
			"net_set_recv_buffer_size(%zu) failed: %m",
			set->socket_recv_buffer_size);
	}

	conn_event = event_create(server->event);
	conn->conn.event_parent = conn_event;
	connection_init_server(server->conn_list, &conn->conn, NULL,
			       fd_in, fd_out);
	conn->event = conn->conn.event;
	event_unref(&conn_event);

	if (!ssl)
		http_server_connection_ready(conn);
	http_server_connection_start_idle_timeout(conn);

	e_debug(conn->event, "Connection created");
	return conn;
}

void http_server_connection_ref(struct http_server_connection *conn)
{
	i_assert(conn->refcount > 0);
	conn->refcount++;
}

static void
http_server_connection_disconnect(struct http_server_connection *conn,
	const char *reason)
{
	struct http_server_request *req, *req_next;

	if (conn->closed)
		return;

	if (reason == NULL)
		reason = "Connection closed";
	e_debug(conn->event, "Disconnected: %s", reason);
	conn->disconnect_reason = i_strdup(reason);
	conn->closed = TRUE;

	/* Preserve statistics */
	http_server_connection_update_stats(conn);

	if (conn->incoming_payload != NULL) {
		/* The stream is still accessed by lib-http caller. */
		i_stream_remove_destroy_callback(conn->incoming_payload,
						 http_server_payload_destroyed);
		conn->incoming_payload = NULL;
	}
	if (conn->payload_handler != NULL)
		http_server_payload_handler_destroy(&conn->payload_handler);

	/* Drop all requests before connection is closed */
	req = conn->request_queue_head;
	while (req != NULL) {
		req_next = req->next;
		http_server_request_abort(&req, reason);
		req = req_next;
	}

	timeout_remove(&conn->to_input);
	timeout_remove(&conn->to_idle);
	io_remove(&conn->io_resp_payload);
	if (conn->conn.output != NULL)
		o_stream_uncork(conn->conn.output);

	if (conn->http_parser != NULL)
		http_request_parser_deinit(&conn->http_parser);
	connection_disconnect(&conn->conn);
}

bool http_server_connection_unref(struct http_server_connection **_conn)
{
	struct http_server_connection *conn = *_conn;

	i_assert(conn->refcount > 0);

	*_conn = NULL;
	if (--conn->refcount > 0)
		return TRUE;

	http_server_connection_disconnect(conn, NULL);

	e_debug(conn->event, "Connection destroy");

	ssl_iostream_destroy(&conn->ssl_iostream);
	connection_deinit(&conn->conn);

	if (conn->callbacks != NULL &&
	    conn->callbacks->connection_destroy != NULL) T_BEGIN {
		conn->callbacks->connection_destroy(conn->context,
						    conn->disconnect_reason);
	} T_END;

	i_free(conn->disconnect_reason);
	i_free(conn);
	return FALSE;
}

static bool
http_server_connection_unref_is_closed(struct http_server_connection *conn)
{
	bool closed = conn->closed;

	if (!http_server_connection_unref(&conn))
		closed = TRUE;
	return closed;
}

void http_server_connection_close(struct http_server_connection **_conn,
				  const char *reason)
{
	struct http_server_connection *conn = *_conn;

	http_server_connection_disconnect(conn, reason);
	http_server_connection_unref(_conn);
}

void http_server_connection_tunnel(struct http_server_connection **_conn,
				   http_server_tunnel_callback_t callback,
				   void *context)
{
	struct http_server_connection *conn = *_conn;
	struct http_server_tunnel tunnel;

	/* Preserve statistics */
	http_server_connection_update_stats(conn);

	i_zero(&tunnel);
	tunnel.input = conn->conn.input;
	tunnel.output = conn->conn.output;
	tunnel.fd_in = conn->conn.fd_in;
	tunnel.fd_out = conn->conn.fd_out;

	conn->conn.input = NULL;
	conn->conn.output = NULL;
	conn->conn.fd_in = conn->conn.fd_out = -1;
	http_server_connection_close(_conn, "Tunnel initiated");

	callback(context, &tunnel);
}

struct ioloop *
http_server_connection_switch_ioloop_to(struct http_server_connection *conn,
					struct ioloop *ioloop)
{
	struct ioloop *prev_ioloop = conn->ioloop;

	if (conn->ioloop_switching != NULL)
		return conn->ioloop_switching;

	conn->ioloop = ioloop;
	conn->ioloop_switching = prev_ioloop;
	connection_switch_ioloop_to(&conn->conn, ioloop);
	if (conn->to_input != NULL) {
		conn->to_input =
			io_loop_move_timeout_to(ioloop, &conn->to_input);
	}
	if (conn->to_idle != NULL) {
		conn->to_idle =
			io_loop_move_timeout_to(ioloop, &conn->to_idle);
	}
	if (conn->io_resp_payload != NULL) {
		conn->io_resp_payload =
			io_loop_move_io_to(ioloop, &conn->io_resp_payload);
	}
	if (conn->payload_handler != NULL) {
		http_server_payload_handler_switch_ioloop(
			conn->payload_handler, ioloop);
	}
	if (conn->incoming_payload != NULL)
		i_stream_switch_ioloop_to(conn->incoming_payload, ioloop);
	conn->ioloop_switching = NULL;

	return prev_ioloop;
}

struct ioloop *
http_server_connection_switch_ioloop(struct http_server_connection *conn)
{
	return http_server_connection_switch_ioloop_to(conn, current_ioloop);
}
