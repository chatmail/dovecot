/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "auth-client-private.h"

struct event_category event_category_auth_client = {
	.name = "auth-client"
};

struct auth_client *
auth_client_init(const char *auth_socket_path, unsigned int client_pid,
		 bool debug)
{
	struct auth_client *client;

	client = i_new(struct auth_client, 1);
	client->client_pid = client_pid;
	client->auth_socket_path = i_strdup(auth_socket_path);
	client->debug = debug;
	client->connect_timeout_msecs = AUTH_CONNECT_TIMEOUT_MSECS;
	client->clist = auth_client_connection_list_init();

	client->event = event_create(NULL);
	event_add_category(client->event, &event_category_auth_client);
	event_set_append_log_prefix(client->event, "auth-client: ");
	event_set_forced_debug(client->event, client->debug);

	client->conn = auth_client_connection_init(client);
	return client;
}

void auth_client_deinit(struct auth_client **_client)
{
	struct auth_client *client = *_client;

	*_client = NULL;

	auth_client_connection_deinit(&client->conn);
	connection_list_deinit(&client->clist);
	event_unref(&client->event);
	i_free(client->auth_socket_path);
	i_free(client);
}

void auth_client_connect(struct auth_client *client)
{
	if (!client->conn->connected)
		(void)auth_client_connection_connect(client->conn);
}

void auth_client_disconnect(struct auth_client *client, const char *reason)
{
	auth_client_connection_disconnect(client->conn, reason);
}

bool auth_client_is_connected(struct auth_client *client)
{
	/* handshake_received isn't unset immediately after disconnection */
	return client->conn->conn.handshake_received &&
		client->conn->connected;
}

bool auth_client_is_disconnected(struct auth_client *client)
{
	return !client->conn->connected;
}

void auth_client_set_connect_timeout(struct auth_client *client,
				     unsigned int msecs)
{
	client->connect_timeout_msecs = msecs;
}

void auth_client_set_connect_notify(struct auth_client *client,
				    auth_connect_notify_callback_t *callback,
				    void *context)
{
	client->connect_notify_callback = callback;
	client->connect_notify_context = context;
}

const struct auth_mech_desc *
auth_client_get_available_mechs(struct auth_client *client,
				unsigned int *mech_count)
{
	i_assert(auth_client_is_connected(client));

	return array_get(&client->conn->available_auth_mechs, mech_count);
}

const struct auth_mech_desc *
auth_client_find_mech(struct auth_client *client, const char *name)
{
	const struct auth_mech_desc *mech;

	array_foreach(&client->conn->available_auth_mechs, mech) {
		if (strcasecmp(mech->name, name) == 0)
			return mech;
	}
	return NULL;
}

void auth_client_get_connect_id(struct auth_client *client,
				unsigned int *server_pid_r,
				unsigned int *connect_uid_r)
{
	i_assert(auth_client_is_connected(client));

	*server_pid_r = client->conn->server_pid;
	*connect_uid_r = client->conn->connect_uid;
}
