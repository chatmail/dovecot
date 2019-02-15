/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "ioloop.h"
#include "hash.h"
#include "strescape.h"
#include "login-proxy-state.h"

#include <unistd.h>
#include <fcntl.h>

#define NOTIFY_RETRY_REOPEN_MSECS (60*1000)

struct login_proxy_state {
	HASH_TABLE(struct login_proxy_record *,
		   struct login_proxy_record *) hash;
	pool_t pool;

	const char *notify_path;
	int notify_fd;

	struct timeout *to_reopen;
};

static int login_proxy_state_notify_open(struct login_proxy_state *state);

static unsigned int
login_proxy_record_hash(const struct login_proxy_record *rec)
{
	return net_ip_hash(&rec->ip) ^ rec->port;
}

static int login_proxy_record_cmp(struct login_proxy_record *rec1,
				  struct login_proxy_record *rec2)
{
	if (!net_ip_compare(&rec1->ip, &rec2->ip))
		return 1;

	return (int)rec1->port - (int)rec2->port;
}

struct login_proxy_state *login_proxy_state_init(const char *notify_path)
{
	struct login_proxy_state *state;

	state = i_new(struct login_proxy_state, 1);
	state->pool = pool_alloconly_create("login proxy state", 1024);
	hash_table_create(&state->hash, state->pool, 0,
			  login_proxy_record_hash, login_proxy_record_cmp);
	state->notify_path = p_strdup(state->pool, notify_path);
	state->notify_fd = -1;
	return state;
}

static void login_proxy_state_close(struct login_proxy_state *state)
{
	i_close_fd_path(&state->notify_fd, state->notify_path);
}

void login_proxy_state_deinit(struct login_proxy_state **_state)
{
	struct login_proxy_state *state = *_state;
	struct hash_iterate_context *iter;
	struct login_proxy_record *rec;

	*_state = NULL;

	/* sanity check: */
	iter = hash_table_iterate_init(state->hash);
	while (hash_table_iterate(iter, state->hash, &rec, &rec))
		i_assert(rec->num_waiting_connections == 0);
	hash_table_iterate_deinit(&iter);

	timeout_remove(&state->to_reopen);
	login_proxy_state_close(state);
	hash_table_destroy(&state->hash);
	pool_unref(&state->pool);
	i_free(state);
}

struct login_proxy_record *
login_proxy_state_get(struct login_proxy_state *state,
		      const struct ip_addr *ip, in_port_t port)
{
	struct login_proxy_record *rec, key;

	i_zero(&key);
	key.ip = *ip;
	key.port = port;

	rec = hash_table_lookup(state->hash, &key);
	if (rec == NULL) {
		rec = p_new(state->pool, struct login_proxy_record, 1);
		rec->ip = *ip;
		rec->port = port;
		hash_table_insert(state->hash, rec, rec);
	}
	return rec;
}

static void login_proxy_state_reopen(struct login_proxy_state *state)
{
	timeout_remove(&state->to_reopen);
	(void)login_proxy_state_notify_open(state);
}

static int login_proxy_state_notify_open(struct login_proxy_state *state)
{
	if (state->to_reopen != NULL) {
		/* reopen later */
		return -1;
	}

	state->notify_fd = open(state->notify_path, O_WRONLY);
	if (state->notify_fd == -1) {
		i_error("open(%s) failed: %m", state->notify_path);
		state->to_reopen = timeout_add(NOTIFY_RETRY_REOPEN_MSECS,
					       login_proxy_state_reopen, state);
		return -1;
	}
	fd_set_nonblock(state->notify_fd, TRUE);
	return 0;
}

static bool login_proxy_state_try_notify(struct login_proxy_state *state,
					 const char *user)
{
	size_t len;
	ssize_t ret;

	if (state->notify_fd == -1) {
		if (login_proxy_state_notify_open(state) < 0)
			return TRUE;
		i_assert(state->notify_fd != -1);
	}

	T_BEGIN {
		const char *cmd;

		cmd = t_strconcat(str_tabescape(user), "\n", NULL);
		len = strlen(cmd);
		ret = write(state->notify_fd, cmd, len);
	} T_END;

	if (ret != (ssize_t)len) {
		if (ret < 0)
			i_error("write(%s) failed: %m", state->notify_path);
		else {
			i_error("write(%s) wrote partial update",
				state->notify_path);
		}
		login_proxy_state_close(state);
		/* retry sending */
		return FALSE;
	}
	return TRUE;
}

void login_proxy_state_notify(struct login_proxy_state *state,
			      const char *user)
{
	if (!login_proxy_state_try_notify(state, user))
		(void)login_proxy_state_try_notify(state, user);
}
