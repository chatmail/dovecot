#ifndef WORKER_CONNECTION_H
#define WORKER_CONNECTION_H

#include "indexer.h"

struct indexer_request;
struct connection_list;

struct connection *
worker_connection_create(const char *socket_path,
			 indexer_status_callback_t *callback,
			 struct connection_list *list);
void worker_connection_unref(struct connection **_conn);

struct connection_list *worker_connection_list_create(void);

/* Returns TRUE if worker is connected to (not necessarily handshaked yet) */
bool worker_connection_is_connected(struct connection *conn);

/* After initial handshake the worker process tells how many of its kind
   can be at maximum. This returns the value, of FALSE if handshake isn't
   finished yet. */
bool worker_connection_get_process_limit(struct connection *conn,
					 unsigned int *limit_r);

/* Send a new indexing request for username+mailbox. The status callback is
   called as necessary with the given context. Requests can be queued, but
   only for the same username. */
void worker_connection_request(struct connection *conn,
			       struct indexer_request *request,
			       void *context);
/* Returns TRUE if a request is being handled. */
bool worker_connection_is_busy(struct connection *conn);
/* Returns username of the currently pending requests,
   or NULL if there are none. */
const char *worker_connection_get_username(struct connection *conn);

struct indexer_request *
worker_connection_get_request(struct connection *conn);

#endif
