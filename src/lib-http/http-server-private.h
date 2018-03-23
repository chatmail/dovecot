#ifndef HTTP_SERVER_PRIVATE_H
#define HTTP_SERVER_PRIVATE_H

#include "connection.h"

#include "iostream-pump.h"
#include "http-server.h"
#include "llist.h"

struct http_server_payload_handler;
struct http_server_request;
struct http_server_connection;

/*
 * Defaults
 */

#define HTTP_SERVER_REQUEST_MAX_TARGET_LENGTH 4096

/*
 * Types
 */

enum http_server_request_state {
	/* New request; request header is still being parsed. */
	HTTP_SERVER_REQUEST_STATE_NEW = 0,
	/* Queued request; callback to request handler executing. */	
	HTTP_SERVER_REQUEST_STATE_QUEUED,
	/* Reading request payload; request handler still needs to read more
	   payload. */
	HTTP_SERVER_REQUEST_STATE_PAYLOAD_IN,
	/* This request is being processed; request payload is fully read, but no
	   response is yet submitted */
	HTTP_SERVER_REQUEST_STATE_PROCESSING,
	/* A response is submitted for this request. If not all request payload
	   was read by the handler, it is first skipped on the input.
   */
	HTTP_SERVER_REQUEST_STATE_SUBMITTED_RESPONSE,
	/* Request is ready for response; a response is submitted and the request
	   payload is fully read */
	HTTP_SERVER_REQUEST_STATE_READY_TO_RESPOND,
	/* The response for the request is sent (apart from payload) */
	HTTP_SERVER_REQUEST_STATE_SENT_RESPONSE,
	/* Sending response payload to client */
	HTTP_SERVER_REQUEST_STATE_PAYLOAD_OUT,
	/* Request is finished; still lingering due to references */
	HTTP_SERVER_REQUEST_STATE_FINISHED,
	/* Request is aborted; still lingering due to references */
	HTTP_SERVER_REQUEST_STATE_ABORTED
};

/*
 * Objects
 */

struct http_server_payload_handler {
	struct http_server_request *req;

	void (*switch_ioloop)(struct http_server_payload_handler *handler);
	void (*destroy)(struct http_server_payload_handler *handler);

	bool in_callback:1;
};

struct http_server_response {
	struct http_server_request *request;

	unsigned int status;
	const char *reason;

	string_t *headers;
	time_t date;
	ARRAY_TYPE(http_auth_challenge) auth_challenges;

	struct istream *payload_input;
	uoff_t payload_size, payload_offset;
	struct ostream *payload_output;

	struct ostream *blocking_output;

	http_server_tunnel_callback_t tunnel_callback;
	void *tunnel_context;

	bool have_hdr_connection:1;
	bool have_hdr_date:1;
	bool have_hdr_body_spec:1;

	bool payload_chunked:1;
	bool payload_blocking:1;
	bool payload_direct:1;
	bool payload_corked:1;
	bool submitted:1;
};

struct http_server_request {
	struct http_request req;
	pool_t pool;
	unsigned int refcount;
	unsigned int id;
	int callback_refcount;

	enum http_server_request_state state;

	struct http_server_request *prev, *next;

	struct http_server *server;
	struct http_server_connection *conn;

	struct istream *payload_input;

	struct http_server_response *response;

	void (*destroy_callback)(void *);
	void *destroy_context;

	bool payload_halted:1;
	bool sent_100_continue:1;
	bool delay_destroy:1;
	bool destroy_pending:1;
	bool failed:1;
	bool connection_close:1;
};

struct http_server_connection {
	struct connection conn;
	struct http_server *server;
	unsigned int refcount;

	const struct http_server_callbacks *callbacks;
	void *context;

	unsigned int id; // DEBUG

	struct timeout *to_input, *to_idle;
	struct ssl_iostream *ssl_iostream;
	struct http_request_parser *http_parser;

	struct http_server_request *request_queue_head, *request_queue_tail;
	unsigned int request_queue_count;

	struct istream *incoming_payload;
	struct http_server_payload_handler *payload_handler;

	struct io *io_resp_payload;

	char *disconnect_reason;

	struct http_server_stats stats;

	bool ssl:1;
	bool closed:1;
	bool close_indicated:1;
	bool input_broken:1;
	bool output_locked:1;
	bool in_req_callback:1;  /* performing request callback (busy) */
	bool switching_ioloop:1; /* in the middle of switching ioloop */
};

struct http_server {
	pool_t pool;

	struct http_server_settings set;

	struct ioloop *ioloop;
	struct ssl_iostream_context *ssl_ctx;

	struct connection_list *conn_list;

	bool shutting_down:1;    /* shutting down server */
};

/*
 * Response
 */

void http_server_response_free(struct http_server_response *resp);
int http_server_response_send(struct http_server_response *resp,
			     const char **error_r);
int http_server_response_send_more(struct http_server_response *resp,
				  const char **error_r);

/*
 * Request
 */

static inline const char *
http_server_request_label(struct http_server_request *req)
{
	if (req->req.method == NULL) {
		if (req->req.target_raw == NULL)
			return t_strdup_printf("[Req%u: <NEW>]", req->id);
		return t_strdup_printf("[Req%u: %s <INCOMPLETE>]",
			req->id, req->req.method);
	}
	return t_strdup_printf("[Req%u: %s %s]", req->id,
		req->req.method, req->req.target_raw);
}

static inline bool
http_server_request_is_new(struct http_server_request *req)
{
	return (req->state == HTTP_SERVER_REQUEST_STATE_NEW);
}

static inline bool
http_server_request_version_equals(struct http_server_request *req,
	unsigned int major, unsigned int minor) {
	return (req->req.version_major == major && req->req.version_minor == minor);
}

struct http_server_request *
http_server_request_new(struct http_server_connection *conn);
void http_server_request_destroy(struct http_server_request **_req);
void http_server_request_abort(struct http_server_request **_req,
	const char *reason) ATTR_NULL(2);

bool http_server_request_is_complete(struct http_server_request *req);

void http_server_request_halt_payload(struct http_server_request *req);
void http_server_request_continue_payload(struct http_server_request *req);

void http_server_request_submit_response(struct http_server_request *req);

void http_server_request_ready_to_respond(struct http_server_request *req);
void http_server_request_finished(struct http_server_request *req);

/* payload handler */

void http_server_payload_handler_destroy(
	struct http_server_payload_handler **_handler);
void http_server_payload_handler_switch_ioloop(
	struct http_server_payload_handler *handler);

/*
 * connection
 */

static inline const char *
http_server_connection_label(struct http_server_connection *conn)
{
	return conn->conn.name;
}

static inline void
http_server_connection_add_request(struct http_server_connection *conn,
	struct http_server_request *sreq)
{
	DLLIST2_APPEND(&conn->request_queue_head, &conn->request_queue_tail, sreq);
	conn->request_queue_count++;
}
static inline void
http_server_connection_remove_request(struct http_server_connection *conn,
	struct http_server_request *sreq)
{
	DLLIST2_REMOVE(&conn->request_queue_head, &conn->request_queue_tail, sreq);
	conn->request_queue_count--;
}

struct connection_list *http_server_connection_list_init(void);

bool http_server_connection_shut_down(struct http_server_connection *conn);

void http_server_connection_switch_ioloop(struct http_server_connection *conn);

void http_server_connection_write_failed(struct http_server_connection *conn,
	const char *error);

void http_server_connection_trigger_responses(
	struct http_server_connection *conn);
int http_server_connection_flush(struct http_server_connection *conn);
int http_server_connection_output(struct http_server_connection *conn);

void http_server_connection_tunnel(struct http_server_connection **_conn,
	http_server_tunnel_callback_t callback, void *context);

int http_server_connection_discard_payload(
	struct http_server_connection *conn);
bool http_server_connection_pending_payload(
	struct http_server_connection *conn);

#endif
