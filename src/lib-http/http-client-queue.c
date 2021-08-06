/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "str.h"
#include "str-sanitize.h"
#include "hash.h"
#include "array.h"
#include "bsearch-insert-pos.h"
#include "llist.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "time-util.h"
#include "dns-lookup.h"
#include "http-response-parser.h"

#include "http-client-private.h"

#define TIMEOUT_CMP_MARGIN_USECS 2000

static void
http_client_queue_fail_full(struct http_client_queue *queue,
			    unsigned int status, const char *error, bool all);
static void
http_client_queue_set_delay_timer(struct http_client_queue *queue,
				  struct timeval time);
static void
http_client_queue_set_request_timer(struct http_client_queue *queue,
				    const struct timeval *time);

/*
 * Queue object
 */

static struct http_client_queue *
http_client_queue_find(struct http_client_host *host,
		       const struct http_client_peer_addr *addr)
{
	struct http_client_queue *queue;

	array_foreach_elem(&host->queues, queue) {
		if (http_client_peer_addr_cmp(&queue->addr, addr) == 0)
			return queue;
	}

	return NULL;
}

static struct http_client_queue *
http_client_queue_create(struct http_client_host *host,
			 const struct http_client_peer_addr *addr)
{
	const char *hostname = host->shared->name;
	struct http_client_queue *queue;

	queue = i_new(struct http_client_queue, 1);
	queue->client = host->client;
	queue->host = host;
	queue->addr = *addr;

	switch (addr->type) {
	case HTTP_CLIENT_PEER_ADDR_RAW:
		queue->name = i_strdup_printf("raw://%s:%u",
					      hostname, addr->a.tcp.port);
		queue->addr.a.tcp.https_name = NULL;
		break;
	case HTTP_CLIENT_PEER_ADDR_HTTPS_TUNNEL:
	case HTTP_CLIENT_PEER_ADDR_HTTPS:
		queue->name = i_strdup_printf("https://%s:%u",
					      hostname, addr->a.tcp.port);
		queue->addr_name = i_strdup(addr->a.tcp.https_name);
		queue->addr.a.tcp.https_name = queue->addr_name;
		break;
	case HTTP_CLIENT_PEER_ADDR_HTTP:
		queue->name = i_strdup_printf("http://%s:%u",
					      hostname, addr->a.tcp.port);
		queue->addr.a.tcp.https_name = NULL;
		break;
	case HTTP_CLIENT_PEER_ADDR_UNIX:
		queue->name = i_strdup_printf("unix:%s", addr->a.un.path);
		queue->addr_name = i_strdup(addr->a.un.path);
		queue->addr.a.un.path = queue->addr_name;
		break;
	default:
		i_unreached();
	}

	queue->event = event_create(queue->client->event);
	event_set_append_log_prefix(queue->event,
		t_strdup_printf("queue %s: ", str_sanitize(queue->name, 256)));
	queue->ips_connect_idx = 0;
	i_array_init(&queue->pending_peers, 8);
	i_array_init(&queue->requests, 16);
	i_array_init(&queue->queued_requests, 16);
	i_array_init(&queue->queued_urgent_requests, 16);
	i_array_init(&queue->delayed_requests, 4);
	array_push_back(&host->queues, &queue);

	return queue;
}

struct http_client_queue *
http_client_queue_get(struct http_client_host *host,
		      const struct http_client_peer_addr *addr)
{
	struct http_client_queue *queue;

	queue = http_client_queue_find(host, addr);
	if (queue == NULL)
		queue = http_client_queue_create(host, addr);

	return queue;
}

void http_client_queue_free(struct http_client_queue *queue)
{
	struct http_client_peer *peer;
	ARRAY_TYPE(http_client_peer) peers;

	e_debug(queue->event, "Destroy");

	/* Currently only called when peer is freed, so there is no need to
	   unlink from the peer */

	/* Unlink all peers */
	if (queue->cur_peer != NULL) {
		struct http_client_peer *peer = queue->cur_peer;

		queue->cur_peer = NULL;
		http_client_peer_unlink_queue(peer, queue);
	}
	t_array_init(&peers, array_count(&queue->pending_peers));
	array_copy(&peers.arr, 0, &queue->pending_peers.arr, 0,
		   array_count(&queue->pending_peers));
	array_foreach_elem(&peers, peer)
		http_client_peer_unlink_queue(peer, queue);
	array_free(&queue->pending_peers);

	/* Abort all requests */
	http_client_queue_fail_full(queue, HTTP_CLIENT_REQUEST_ERROR_ABORTED,
				    "Aborted", TRUE);
	array_free(&queue->requests);
	array_free(&queue->queued_requests);
	array_free(&queue->queued_urgent_requests);
	array_free(&queue->delayed_requests);

	/* Cancel timeouts */
	timeout_remove(&queue->to_connect);
	timeout_remove(&queue->to_delayed);

	/* Free */
	event_unref(&queue->event);
	i_free(queue->addr_name);
	i_free(queue->name);
	i_free(queue);
}

/*
 * Error handling
 */

static void
http_client_queue_fail_full(struct http_client_queue *queue,
			    unsigned int status, const char *error, bool all)
{
	ARRAY_TYPE(http_client_request) *req_arr, treqs;
	struct http_client_request *req;
	unsigned int retained = 0;

	/* Abort requests */
	req_arr = &queue->requests;
	t_array_init(&treqs, array_count(req_arr));
	array_copy(&treqs.arr, 0, &req_arr->arr, 0, array_count(req_arr));
	array_foreach_elem(&treqs, req) {
		i_assert(req->state >= HTTP_REQUEST_STATE_QUEUED);
		if (!all &&
			req->state != HTTP_REQUEST_STATE_QUEUED)
			retained++;
		else
			http_client_request_error(&req, status, error);
	}

	/* All queues should be empty now... unless new requests were submitted
	   from the callback. this invariant captures it all: */
	i_assert((retained +
		  array_count(&queue->delayed_requests) +
		  array_count(&queue->queued_requests) +
		  array_count(&queue->queued_urgent_requests)) ==
		 array_count(&queue->requests));
}

static void
http_client_queue_fail(struct http_client_queue *queue,
		       unsigned int status, const char *error)
{
	http_client_queue_fail_full(queue, status, error, FALSE);
}

/*
 * Connection management
 */

static bool
http_client_queue_is_last_connect_ip(struct http_client_queue *queue)
{
	const struct http_client_settings *set =
		&queue->client->set;
	struct http_client_host *host = queue->host;
	unsigned int ips_count = http_client_host_get_ips_count(host);

	i_assert(queue->addr.type != HTTP_CLIENT_PEER_ADDR_UNIX);
	i_assert(queue->ips_connect_idx < ips_count);
	i_assert(queue->ips_connect_start_idx < ips_count);

	/* If a maximum connect attempts > 1 is set, enforce it directly */
	if (set->max_connect_attempts > 1 &&
		queue->connect_attempts >= set->max_connect_attempts)
		return TRUE;

	/* Otherwise, we'll always go through all the IPs. we don't necessarily
	   start connecting from the first IP, so we'll need to treat the IPs as
	   a ring buffer where we automatically wrap back to the first IP
	   when necessary. */
	return ((queue->ips_connect_idx + 1) % ips_count ==
		queue->ips_connect_start_idx);
}

static void
http_client_queue_recover_from_lookup(struct http_client_queue *queue)
{
	struct http_client_host *host = queue->host;
	unsigned int ip_idx;

	i_assert(queue->addr.type != HTTP_CLIENT_PEER_ADDR_UNIX);

	if (queue->cur_peer == NULL) {
		queue->ips_connect_idx = queue->ips_connect_start_idx = 0;
		return;
	}

	if (http_client_host_get_ip_idx(
		host, &queue->cur_peer->shared->addr.a.tcp.ip, &ip_idx)) {
		/* Continue with current peer */
		queue->ips_connect_idx = queue->ips_connect_start_idx = ip_idx;
	} else {
		/* Reset connect attempts */
		queue->ips_connect_idx = queue->ips_connect_start_idx = 0;
	}
}

static void
http_client_queue_soft_connect_timeout(struct http_client_queue *queue)
{
	struct http_client_host *host = queue->host;
	const struct http_client_peer_addr *addr = &queue->addr;
	unsigned int ips_count = http_client_host_get_ips_count(host);
	const char *https_name;

	i_assert(queue->addr.type != HTTP_CLIENT_PEER_ADDR_UNIX);

	timeout_remove(&queue->to_connect);

	if (http_client_queue_is_last_connect_ip(queue)) {
		/* No more IPs to try */
		return;
	}

	/* If our our previous connection attempt takes longer than the
	   soft_connect_timeout, we start a connection attempt to the next IP in
	   parallel */
	https_name = http_client_peer_addr_get_https_name(addr);
	e_debug(queue->event, "Connection to %s%s is taking a long time; "
		"starting parallel connection attempt to next IP",
		http_client_peer_addr2str(addr),
		(https_name == NULL ?
		 "" : t_strdup_printf(" (SSL=%s)", https_name)));

	/* Next IP */
	queue->ips_connect_idx = (queue->ips_connect_idx + 1) % ips_count;

	/* Setup connection to new peer (can start new soft timeout) */
	http_client_queue_connection_setup(queue);
}

static struct http_client_peer *
http_client_queue_connection_attempt(struct http_client_queue *queue)
{
	struct http_client *client = queue->client;
	struct http_client_host *host = queue->host;
	struct http_client_peer *peer;
	struct http_client_peer_addr *addr = &queue->addr;
	unsigned int num_requests =
		array_count(&queue->queued_requests) +
		array_count(&queue->queued_urgent_requests);
	const char *ssl = "";
	int ret;

	if (num_requests == 0)
		return NULL;

	/* Check whether host IPs are still up-to-date */
	ret = http_client_host_refresh(host);
	if (ret < 0) {
		/* Performing asynchronous lookup */
		timeout_remove(&queue->to_connect);
		return NULL;
	}
	if (ret > 0) {
		/* New lookup performed */
		http_client_queue_recover_from_lookup(queue);
	}

	/* Update our peer address */
	if (queue->addr.type != HTTP_CLIENT_PEER_ADDR_UNIX) {
		const struct ip_addr *ip =
			http_client_host_get_ip(host, queue->ips_connect_idx);

		queue->addr.a.tcp.ip = *ip;
		ssl = http_client_peer_addr_get_https_name(addr);
		ssl = (ssl == NULL ? "" : t_strdup_printf(" (SSL=%s)", ssl));
	}

	/* Already got a peer? */
	peer = NULL;
	if (queue->cur_peer != NULL) {
		i_assert(array_count(&queue->pending_peers) == 0);

		/* Is it still the one we want? */
		if (http_client_peer_addr_cmp(
			addr, &queue->cur_peer->shared->addr) == 0) {
			/* Is it still connected? */
			if (http_client_peer_is_connected(queue->cur_peer)) {
				/* Yes */
				e_debug(queue->event,
					"Using existing connection to %s%s "
					"(%u requests pending)",
					http_client_peer_addr2str(addr),
					ssl, num_requests);

				/* Handle requests; */
				http_client_peer_trigger_request_handler(
					queue->cur_peer);
				return queue->cur_peer;
			}
			/* No */
			peer = queue->cur_peer;
		} else {
			/* Peer is not relevant to this queue anymore */
			http_client_peer_unlink_queue(queue->cur_peer, queue);
		}

		queue->cur_peer = NULL;
	}

	if (peer == NULL)
		peer = http_client_peer_get(queue->client, addr);

	e_debug(queue->event,
		"Setting up connection to %s%s (%u requests pending)",
		http_client_peer_addr2str(addr), ssl, num_requests);

	/* Create provisional link between queue and peer */
	http_client_peer_link_queue(peer, queue);

	/* Handle requests; creates new connections when needed/possible */
	http_client_peer_trigger_request_handler(peer);

	if (http_client_peer_is_connected(peer)) {
		/* Drop any pending peers */
		if (array_count(&queue->pending_peers) > 0) {
			struct http_client_peer *pending_peer;

			array_foreach_elem(&queue->pending_peers, pending_peer) {
				if (pending_peer == peer) {
					/* This can happen with shared clients
					 */
					continue;
				}
				i_assert(http_client_peer_addr_cmp(
					&pending_peer->shared->addr, addr) != 0);
				http_client_peer_unlink_queue(pending_peer, queue);
			}
			array_clear(&queue->pending_peers);
		}
		queue->cur_peer = peer;

		http_client_peer_trigger_request_handler(queue->cur_peer);

	} else {
		struct http_client_peer *pending_peer;
		unsigned int msecs;
		bool new_peer = TRUE;

		/* Not already connected, wait for connections */

		/* We may be waiting for this peer already */
		array_foreach_elem(&queue->pending_peers, pending_peer) {
			if (http_client_peer_addr_cmp(
				&pending_peer->shared->addr, addr) == 0) {
				i_assert(pending_peer == peer);
				new_peer = FALSE;
				break;
			}
		}
		if (new_peer) {
			e_debug(queue->event, "Started new connection to %s%s",
				http_client_peer_addr2str(addr), ssl);

			array_push_back(&queue->pending_peers, &peer);
			if (queue->connect_attempts++ == 0)
				queue->first_connect_time = ioloop_timeval;
		}

		/* Start soft connect time-out
		   (but only if we have another IP left) */
		if (queue->addr.type != HTTP_CLIENT_PEER_ADDR_UNIX) {
			msecs = client->set.soft_connect_timeout_msecs;
			if (!http_client_queue_is_last_connect_ip(queue) &&
			    msecs > 0 && queue->to_connect == NULL) {
				queue->to_connect = timeout_add_to(
					client->ioloop, msecs,
					http_client_queue_soft_connect_timeout,
					queue);
			}
		}
	}

	return peer;
}

void http_client_queue_connection_setup(struct http_client_queue *queue)
{
	(void)http_client_queue_connection_attempt(queue);
}

unsigned int
http_client_queue_host_lookup_done(struct http_client_queue *queue)
{
	unsigned int reqs_pending =
		http_client_queue_requests_pending(queue, NULL);

	http_client_queue_recover_from_lookup(queue);
	if (reqs_pending > 0)
		http_client_queue_connection_setup(queue);
	return reqs_pending;
}

void http_client_queue_host_lookup_failure(
	struct http_client_queue *queue, const char *error)
{
	http_client_queue_fail(
		queue, HTTP_CLIENT_REQUEST_ERROR_HOST_LOOKUP_FAILED, error);
}

void http_client_queue_connection_success(struct http_client_queue *queue,
					  struct http_client_peer *peer)
{
	const struct http_client_peer_addr *addr = &peer->shared->addr;
	struct http_client_host *host = queue->host;

	if (http_client_host_ready(host) &&
	    queue->addr.type != HTTP_CLIENT_PEER_ADDR_UNIX) {
		/* We achieved at least one connection the the addr->ip */
		if (!http_client_host_get_ip_idx(
			host, &addr->a.tcp.ip, &queue->ips_connect_start_idx)) {
			/* list of IPs changed during connect */
			queue->ips_connect_start_idx = 0;
		}
	}

	/* Reset attempt counter */
	queue->connect_attempts = 0;

	/* stop soft connect time-out */
	timeout_remove(&queue->to_connect);

	/* Drop all other attempts to the hport. note that we get here whenever
	   a connection is successfully created, so pending_peers array
	   may be empty. */
	if (array_count(&queue->pending_peers) > 0) {
		struct http_client_peer *pending_peer;

		array_foreach_elem(&queue->pending_peers, pending_peer) {
			if (pending_peer == peer) {
				/* Don't drop any connections to the
				   successfully connected peer, even if some of
				   the connections are pending. they may be
				   intended for urgent requests. */
				i_assert(queue->cur_peer == NULL);
				queue->cur_peer = pending_peer;
				continue;
			}
			/* Unlink this queue from the peer; if this was the
			   last/only queue, the peer will be freed, closing all
			   connections.
			 */
			http_client_peer_unlink_queue(pending_peer, queue);
		}

		array_clear(&queue->pending_peers);
		i_assert(queue->cur_peer != NULL);
	}
}

void http_client_queue_connection_failure(struct http_client_queue *queue,
					  struct http_client_peer *peer,
					  const char *reason)
{
	const struct http_client_settings *set =
		&queue->client->set;
	const struct http_client_peer_addr *addr = &peer->shared->addr;
	const char *https_name = http_client_peer_addr_get_https_name(addr);
	struct http_client_host *host = queue->host;
	unsigned int ips_count = http_client_host_get_ips_count(host);
	struct http_client_peer *const *peer_idx;
	unsigned int num_requests =
		array_count(&queue->queued_requests) +
		array_count(&queue->queued_urgent_requests);

	e_debug(queue->event,
		"Failed to set up connection to %s%s: %s "
		"(%u peers pending, %u requests pending)",
		http_client_peer_addr2str(addr),
		(https_name == NULL ?
		 "" : t_strdup_printf(" (SSL=%s)", https_name)),
		reason, array_count(&queue->pending_peers), num_requests);

	http_client_peer_unlink_queue(peer, queue);

	if (array_count(&queue->pending_peers) == 0) {
		i_assert(queue->cur_peer == NULL || queue->cur_peer == peer);
		queue->cur_peer = NULL;
	} else {
		bool found = FALSE;

		i_assert(queue->cur_peer == NULL);

		/* We're still doing the initial connections to this hport. if
		   we're also doing parallel connections with soft timeouts
		   (pending_peer_count>1), wait for them to finish first. */
		array_foreach(&queue->pending_peers, peer_idx) {
			if (*peer_idx == peer) {
				array_delete(&queue->pending_peers,
					     array_foreach_idx(
						&queue->pending_peers,
						peer_idx), 1);
				found = TRUE;
				break;
			}
		}
		i_assert(found);
		if (array_count(&queue->pending_peers) > 0) {
			e_debug(queue->event,
				"Waiting for remaining pending peers.");
			return;
		}

		/* One of the connections failed. if we're not using soft
		   timeouts, we need to try to connect to the next IP. if we are
		   using soft timeouts, we've already tried all of the IPs by
		   now. */
		timeout_remove(&queue->to_connect);

		if (queue->addr.type == HTTP_CLIENT_PEER_ADDR_UNIX) {
			http_client_queue_fail(
				queue, HTTP_CLIENT_REQUEST_ERROR_CONNECT_FAILED,
				reason);
			return;
		}
	}

	if (http_client_queue_is_last_connect_ip(queue)) {
		if (array_count(&queue->pending_peers) > 0) {
			/* Other connection attempts still pending */
			return;
		}

		/* All IPs failed up until here and we allow no more connect
		   attempts, but try the next ones on the next request. */
		queue->ips_connect_idx = queue->ips_connect_start_idx =
			(queue->ips_connect_idx + 1) % ips_count;

		if (set->max_connect_attempts == 0 ||
		    queue->connect_attempts >= set->max_connect_attempts) {

			e_debug(queue->event,
				"Failed to set up any connection; "
				"failing all queued requests");
			if (queue->connect_attempts > 1) {
				unsigned int total_msecs =
					timeval_diff_msecs(&ioloop_timeval,
							   &queue->first_connect_time);
				reason = t_strdup_printf(
					"%s (%u attempts in %u.%03u secs)",
					reason, queue->connect_attempts,
					total_msecs/1000, total_msecs%1000);
			}
			queue->connect_attempts = 0;
			http_client_queue_fail(
				queue, HTTP_CLIENT_REQUEST_ERROR_CONNECT_FAILED,
				reason);
			return;
		}
	} else {
		queue->ips_connect_idx =
			(queue->ips_connect_idx + 1) % ips_count;
	}

	if (http_client_queue_connection_attempt(queue) != peer)
		http_client_peer_unlink_queue(peer, queue);
	return;
}

void http_client_queue_peer_disconnected(struct http_client_queue *queue,
					 struct http_client_peer *peer)
{
	struct http_client_peer *const *peer_idx;

	if (queue->cur_peer == peer) {
		queue->cur_peer = NULL;
		return;
	}

	array_foreach(&queue->pending_peers, peer_idx) {
		if (*peer_idx == peer) {
			array_delete(&queue->pending_peers,
				     array_foreach_idx(&queue->pending_peers,
						       peer_idx), 1);
			break;
		}
	}
}

/*
 * Main request queue
 */

void http_client_queue_drop_request(struct http_client_queue *queue,
				    struct http_client_request *req)
{
	struct http_client_request **reqs;
	unsigned int count, i;

	e_debug(queue->event,
		"Dropping request %s", http_client_request_label(req));

	/* Drop from queue */
	if (req->urgent) {
		reqs = array_get_modifiable(&queue->queued_urgent_requests,
					    &count);
		for (i = 0; i < count; i++) {
			if (reqs[i] == req) {
				array_delete(&queue->queued_urgent_requests,
					     i, 1);
				break;
			}
		}
	} else {
		reqs = array_get_modifiable(&queue->queued_requests, &count);
		for (i = 0; i < count; i++) {
			if (reqs[i] == req) {
				array_delete(&queue->queued_requests, i, 1);
				break;
			}
		}
	}

	/* Drop from delay queue */
	if (req->release_time.tv_sec > 0) {
		reqs = array_get_modifiable(&queue->delayed_requests, &count);
		for (i = 0; i < count; i++) {
			if (reqs[i] == req)
				break;
		}
		if (i < count) {
			if (i == 0) {
				if (queue->to_delayed != NULL) {
					timeout_remove(&queue->to_delayed);
					if (count > 1) {
						i_assert(reqs[1]->release_time.tv_sec > 0);
						http_client_queue_set_delay_timer(
							queue, reqs[1]->release_time);
					}
				}
			}
			array_delete(&queue->delayed_requests, i, 1);
		}
	}

	/* Drop from main request list */
	reqs = array_get_modifiable(&queue->requests, &count);
	for (i = 0; i < count; i++) {
		if (reqs[i] == req)
			break;
	}
	i_assert(i < count);

	if (i == 0) {
		if (queue->to_request != NULL) {
			timeout_remove(&queue->to_request);
			if (count > 1 && reqs[1]->timeout_time.tv_sec > 0) {
				http_client_queue_set_request_timer(queue,
					&reqs[1]->timeout_time);
			}
		}
	}
	req->queue = NULL;
	array_delete(&queue->requests, i, 1);

	if (array_count(&queue->requests) == 0)
		http_client_host_check_idle(queue->host);
	return;
}

static void http_client_queue_request_timeout(struct http_client_queue *queue)
{
	struct http_client_request *const *reqs;
	ARRAY_TYPE(http_client_request) failed_requests;
	struct timeval new_to = { 0, 0 };
	string_t *str;
	size_t prefix_size;
	unsigned int count, i;

	e_debug(queue->event, "Timeout (now: %s.%03lu)",
		t_strflocaltime("%Y-%m-%d %H:%M:%S", ioloop_timeval.tv_sec),
		((unsigned long)ioloop_timeval.tv_usec) / 1000);

	timeout_remove(&queue->to_request);

	/* Collect failed requests */
	reqs = array_get(&queue->requests, &count);
	i_assert(count > 0);
	t_array_init(&failed_requests, count);
	for (i = 0; i < count; i++) {
		if (reqs[i]->timeout_time.tv_sec > 0 &&
		    timeval_cmp_margin(&reqs[i]->timeout_time,
				       &ioloop_timeval,
				       TIMEOUT_CMP_MARGIN_USECS) > 0) {
			break;
		}
		array_push_back(&failed_requests, &reqs[i]);
	}

	/* Update timeout */
	if (i < count)
		new_to = reqs[i]->timeout_time;

	str = t_str_new(64);
	str_append(str, "Request ");
	prefix_size = str_len(str);

	/* Abort all failed request */
	reqs = array_get(&failed_requests, &count);
	i_assert(count > 0); /* At least one request timed out */
	for (i = 0; i < count; i++) {
		struct http_client_request *req = reqs[i];

		str_truncate(str, prefix_size);
		http_client_request_append_stats_text(req, str);

		e_debug(queue->event,
			"Absolute timeout expired for request %s (%s)",
			http_client_request_label(req), str_c(str));
		http_client_request_error(
			&req, HTTP_CLIENT_REQUEST_ERROR_TIMED_OUT,
			t_strdup_printf(
				"Absolute request timeout expired (%s)",
				str_c(str)));
	}

	if (new_to.tv_sec > 0) {
		e_debug(queue->event, "New timeout");
		http_client_queue_set_request_timer(queue, &new_to);
	}
}

static void
http_client_queue_set_request_timer(struct http_client_queue *queue,
				    const struct timeval *time)
{
	i_assert(time->tv_sec > 0);
	timeout_remove(&queue->to_request);

	e_debug(queue->event,
		"Set request timeout to %s.%03lu (now: %s.%03lu)",
		t_strflocaltime("%Y-%m-%d %H:%M:%S", time->tv_sec),
		((unsigned long)time->tv_usec) / 1000,
		t_strflocaltime("%Y-%m-%d %H:%M:%S", ioloop_timeval.tv_sec),
		((unsigned long)ioloop_timeval.tv_usec) / 1000);

	/* Set timer */
	queue->to_request = timeout_add_absolute_to(
		queue->client->ioloop, time,
		http_client_queue_request_timeout, queue);
}

static int
http_client_queue_request_timeout_cmp(struct http_client_request *const *req1,
				      struct http_client_request *const *req2)
{
	int ret;

	/* 0 means no timeout */
	if ((*req1)->timeout_time.tv_sec == 0) {
		if ((*req2)->timeout_time.tv_sec == 0) {
			/* sort by age */
			ret = timeval_cmp(&(*req1)->submit_time,
					  &(*req2)->submit_time);
			if (ret != 0)
				return ret;
		} else {
			return 1;
		}
	} else if ((*req2)->timeout_time.tv_sec == 0) {
		return -1;

	/* Sort by timeout */
	} else if ((ret = timeval_cmp(&(*req1)->timeout_time,
				      &(*req2)->timeout_time)) != 0) {
		return ret;
	}

	/* Sort by minimum attempts for fairness */
	return ((int)(*req2)->attempts - (int)(*req1)->attempts);
}

static void
http_client_queue_submit_now(struct http_client_queue *queue,
			     struct http_client_request *req)
{
	ARRAY_TYPE(http_client_request) *req_queue;

	req->release_time.tv_sec = 0;
	req->release_time.tv_usec = 0;

	if (req->urgent)
		req_queue = &queue->queued_urgent_requests;
	else
		req_queue = &queue->queued_requests;

	/* Enqueue */
	if (req->timeout_time.tv_sec == 0) {
		/* No timeout; enqueue at end */
		array_push_back(req_queue, &req);
	} else if (timeval_diff_msecs(&req->timeout_time,
				      &ioloop_timeval) <= 1) {
		/* Pretty much already timed out; don't bother */
		return;
	} else {
		unsigned int insert_idx;

		/* Keep transmission queue sorted earliest timeout first */
		(void)array_bsearch_insert_pos(
			req_queue, &req,
			http_client_queue_request_timeout_cmp, &insert_idx);
		array_insert(req_queue, insert_idx, &req, 1);
	}

	http_client_queue_connection_setup(queue);
}

/*
 * Delayed request queue
 */

static void
http_client_queue_delay_timeout(struct http_client_queue *queue)
{
	struct http_client_request *const *reqs;
	unsigned int count, i, finished;

	timeout_remove(&queue->to_delayed);
	io_loop_time_refresh();

	finished = 0;
	reqs = array_get(&queue->delayed_requests, &count);
	for (i = 0; i < count; i++) {
		if (timeval_cmp_margin(&reqs[i]->release_time,
				       &ioloop_timeval,
				       TIMEOUT_CMP_MARGIN_USECS) > 0) {
			break;
		}

		e_debug(queue->event, "Activated delayed request %s%s",
			http_client_request_label(reqs[i]),
			(reqs[i]->urgent ? " (urgent)" : ""));
		http_client_queue_submit_now(queue, reqs[i]);
		finished++;
	}
	if (i < count)
		http_client_queue_set_delay_timer(queue, reqs[i]->release_time);
	array_delete(&queue->delayed_requests, 0, finished);
}

static void
http_client_queue_set_delay_timer(struct http_client_queue *queue,
				  struct timeval time)
{
	struct http_client *client = queue->client;
	int usecs = timeval_diff_usecs(&time, &ioloop_timeval);
	int msecs;

	/* Round up to nearest microsecond */
	msecs = (usecs + 999) / 1000;

	/* Set timer */
	timeout_remove(&queue->to_delayed);
	queue->to_delayed = timeout_add_to(
		client->ioloop, msecs,
		http_client_queue_delay_timeout, queue);
}

static int
http_client_queue_delayed_cmp(struct http_client_request *const *req1,
			      struct http_client_request *const *req2)
{
	return timeval_cmp(&(*req1)->release_time, &(*req2)->release_time);
}

/*
 * Request submission
 */

void http_client_queue_submit_request(struct http_client_queue *queue,
				      struct http_client_request *req)
{
	unsigned int insert_idx;

	if (req->queue != NULL)
		http_client_queue_drop_request(req->queue, req);
	req->queue = queue;

	/* Check delay vs timeout */
	if (req->release_time.tv_sec > 0 && req->timeout_time.tv_sec > 0 &&
	    timeval_cmp_margin(&req->release_time, &req->timeout_time,
			       TIMEOUT_CMP_MARGIN_USECS) >= 0) {
		/* Release time is later than absolute timeout */
		req->release_time.tv_sec = 0;
		req->release_time.tv_usec = 0;

		/* Timeout rightaway */
		req->timeout_time = ioloop_timeval;

		e_debug(queue->event,
			"Delayed request %s%s already timed out",
			http_client_request_label(req),
			(req->urgent ? " (urgent)" : ""));
	}

	/* Add to main request list */
	if (req->timeout_time.tv_sec == 0) {
		/* No timeout; just append */
		array_push_back(&queue->requests, &req);
	} else {
		unsigned int insert_idx;

		/* Keep main request list sorted earliest timeout first */
		(void)array_bsearch_insert_pos(
			&queue->requests, &req,
			http_client_queue_request_timeout_cmp, &insert_idx);
		array_insert(&queue->requests, insert_idx, &req, 1);

		/* Now first in queue; update timer */
		if (insert_idx == 0) {
			http_client_queue_set_request_timer(queue,
							    &req->timeout_time);
		}
	}

	/* Handle delay */
	if (req->release_time.tv_sec > 0) {
		io_loop_time_refresh();

		if (timeval_cmp_margin(&req->release_time, &ioloop_timeval,
				       TIMEOUT_CMP_MARGIN_USECS) > 0) {
			e_debug(queue->event,
				"Delayed request %s%s submitted "
				"(time remaining: %d msecs)",
				http_client_request_label(req),
				(req->urgent ? " (urgent)" : ""),
				timeval_diff_msecs(&req->release_time,
						   &ioloop_timeval));

			(void)array_bsearch_insert_pos(
				&queue->delayed_requests, &req,
				http_client_queue_delayed_cmp, &insert_idx);
			array_insert(&queue->delayed_requests, insert_idx,
				     &req, 1);
			if (insert_idx == 0) {
				http_client_queue_set_delay_timer(
					queue, req->release_time);
			}
			return;
		}
	}

	http_client_queue_submit_now(queue, req);
}

/*
 * Request retrieval
 */

struct http_client_request *
http_client_queue_claim_request(struct http_client_queue *queue,
				const struct http_client_peer_addr *addr,
				bool no_urgent)
{
	struct http_client_request *const *requests;
	struct http_client_request *req;
	unsigned int i, count;

	count = 0;
	if (!no_urgent)
	 	requests = array_get(&queue->queued_urgent_requests, &count);

	if (count == 0)
	 	requests = array_get(&queue->queued_requests, &count);
	if (count == 0)
		return NULL;
	i = 0;
	req = requests[i];
	if (req->urgent)
		array_delete(&queue->queued_urgent_requests, i, 1);
	else
		array_delete(&queue->queued_requests, i, 1);

	e_debug(queue->event,
		"Connection to peer %s claimed request %s %s",
		http_client_peer_addr2str(addr), http_client_request_label(req),
		(req->urgent ? "(urgent)" : ""));

	return req;
}

unsigned int
http_client_queue_requests_pending(struct http_client_queue *queue,
				   unsigned int *num_urgent_r)
{
	unsigned int urg_count = array_count(&queue->queued_urgent_requests);

	if (num_urgent_r != NULL)
		*num_urgent_r = urg_count;
	return array_count(&queue->queued_requests) + urg_count;
}

unsigned int http_client_queue_requests_active(struct http_client_queue *queue)
{
	return array_count(&queue->requests);
}

/*
 * Ioloop
 */

void http_client_queue_switch_ioloop(struct http_client_queue *queue)
{
	if (queue->to_connect != NULL)
		queue->to_connect = io_loop_move_timeout(&queue->to_connect);
	if (queue->to_request != NULL)
		queue->to_request = io_loop_move_timeout(&queue->to_request);
	if (queue->to_delayed != NULL)
		queue->to_delayed = io_loop_move_timeout(&queue->to_delayed);
}
