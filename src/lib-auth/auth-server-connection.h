#ifndef AUTH_SERVER_CONNECTION_H
#define AUTH_SERVER_CONNECTION_H

struct auth_server_connection {
	pool_t pool;

	struct auth_client *client;
	int fd;
	time_t last_connect;

	struct io *io;
	struct timeout *to;
	struct istream *input;
	struct ostream *output;

	unsigned int server_pid;
	unsigned int connect_uid;
	char *cookie;

	ARRAY(struct auth_mech_desc) available_auth_mechs;

	/* id => request */
	HASH_TABLE(void *, struct auth_client_request *) requests;

	bool version_received:1;
	bool handshake_received:1;
	bool has_plain_mech:1;
	bool connected:1;
};

struct auth_server_connection *
auth_server_connection_init(struct auth_client *client);
void auth_server_connection_deinit(struct auth_server_connection **conn);

int auth_server_connection_connect(struct auth_server_connection *conn);
void auth_server_connection_disconnect(struct auth_server_connection *conn,
				       const char *reason);

/* Queues a new request. Must not be called if connection is not connected. */
unsigned int
auth_server_connection_add_request(struct auth_server_connection *conn,
				   struct auth_client_request *request);
void auth_server_connection_remove_request(struct auth_server_connection *conn,
					   unsigned int id);
#endif
