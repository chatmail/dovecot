#ifndef SMTP_CLIENT_PRIVATE_H
#define SMTP_CLIENT_PRIVATE_H

#include "connection.h"

#include "smtp-common.h"
#include "smtp-params.h"
#include "smtp-client.h"
#include "smtp-client-command.h"
#include "smtp-client-transaction.h"
#include "smtp-client-connection.h"

#define SMTP_CLIENT_DATA_CHUNK_SIZE IO_BLOCK_SIZE

struct smtp_client_command {
	pool_t pool;
	unsigned int refcount;

	struct smtp_client_command *prev, *next;

	buffer_t *data;
	unsigned int send_pos;
	const char *name;

	enum smtp_client_command_flags flags;

	struct smtp_client_connection *conn;
	enum smtp_client_command_state state;
	unsigned int replies_expected;
	unsigned int replies_seen;

	struct istream *stream;
	uoff_t stream_size;

	smtp_client_command_callback_t *callback;
	void *context;

	void (*abort_callback)(void *context);
	void *abort_context;

	void (*sent_callback)(void *context);
	void *sent_context;

	bool has_stream:1;
	bool stream_dot:1;
	bool ehlo:1;
	bool locked:1;
	bool plug:1;
	bool aborting:1;
};

struct smtp_client_transaction_rcpt {
	pool_t pool;
	struct smtp_client_transaction *trans;

	struct smtp_address *rcpt_to;
	struct smtp_params_rcpt rcpt_params;

	smtp_client_command_callback_t *rcpt_callback;
	smtp_client_command_callback_t *data_callback;
	void *context;

	struct smtp_client_command *cmd_rcpt_to;

	bool failed:1;
};

struct smtp_client_transaction {
	pool_t pool;
	int refcount;

	struct smtp_client_transaction *prev, *next;

	struct smtp_client_connection *conn;
	struct smtp_address *mail_from;
	struct smtp_params_mail mail_params;

	enum smtp_client_transaction_state state;
	struct smtp_client_command *cmd_mail_from, *cmd_data;
	struct smtp_client_command *cmd_plug, *cmd_last;
	struct smtp_reply *failure;

	smtp_client_command_callback_t *mail_from_callback;
	void *mail_from_context;

	ARRAY(struct smtp_client_transaction_rcpt *) rcpts, rcpts_pending;
	unsigned int rcpts_next_send_idx;
	unsigned int rcpt_next_data_idx;

	struct istream *data_input;
	smtp_client_command_callback_t *data_callback;
	void *data_context;

	smtp_client_transaction_callback_t *callback;
	void *context;

	struct smtp_client_transaction_times times;

	unsigned int finish_timeout_msecs;
	struct timeout *to_finish, *to_send;

	bool data_provided:1;
	bool finished:1;
	bool submitted_data:1;
};

struct smtp_client_connection {
	struct connection conn;
	pool_t pool;
	int refcount;

	struct smtp_client *client;
	unsigned int id;
	char *label;

	enum smtp_protocol protocol;
	const char *host;
	in_port_t port;
	enum smtp_client_connection_ssl_mode ssl_mode;

	struct smtp_client_settings set;
	char *password;

	enum smtp_capability capabilities;
	pool_t cap_pool;
	const char **cap_auth_mechanisms;
	const char **cap_xclient_args;
	uoff_t cap_size;

	struct smtp_reply_parser *reply_parser;
	struct smtp_reply reply;

	struct dns_lookup *dns_lookup;
	struct dsasl_client *sasl_client;
	struct timeout *to_connect, *to_trans, *to_commands;

	struct istream *raw_input;
	struct ostream *raw_output, *dot_output;

	struct ssl_iostream_context *ssl_ctx;
	struct ssl_iostream *ssl_iostream;

	enum smtp_client_connection_state state;

	smtp_client_command_callback_t *login_callback;
	void *login_context;

	/* commands pending in queue to be sent */
	struct smtp_client_command *cmd_send_queue_head, *cmd_send_queue_tail;
	unsigned int cmd_send_queue_count;
	/* commands that have been sent, waiting for response */
	struct smtp_client_command *cmd_wait_list_head, *cmd_wait_list_tail;
	unsigned int cmd_wait_list_count;

	/* active transactions */
	struct smtp_client_transaction *transactions_head, *transactions_tail;

	unsigned int ips_count, prev_connect_idx;
	struct ip_addr *ips;

	bool old_smtp:1;
	bool authenticated:1;
	bool initial_xclient_sent:1;
	bool connect_failed:1;
	bool handshake_failed:1;
	bool corked:1;
	bool sent_quit:1;
	bool sending_command:1;
	bool reset_needed:1;
	bool destroying:1;
	bool closed:1;
};

struct smtp_client {
	pool_t pool;

	struct smtp_client_settings set;

	struct ioloop *ioloop;
	struct ssl_iostream_context *ssl_ctx;

	struct connection_list *conn_list;
};

/*
 * Command
 */

void smtp_client_command_free(struct smtp_client_command *cmd);
int smtp_client_command_send_more(struct smtp_client_connection *conn);
int smtp_client_command_input_reply(struct smtp_client_command *cmd,
				    const struct smtp_reply *reply);

void smtp_client_command_fail(struct smtp_client_command **_cmd,
			      unsigned int status, const char *error);
void smtp_client_command_fail_reply(struct smtp_client_command **_cmd,
				    const struct smtp_reply *reply);

void smtp_client_commands_list_abort(struct smtp_client_command *cmds_list,
				     unsigned int cmds_list_count);
void smtp_client_commands_list_fail_reply(
	struct smtp_client_command *cmds_list, unsigned int cmds_list_count,
	const struct smtp_reply *reply);

/*
 * Transaction
 */

void smtp_client_transaction_connection_result(
	struct smtp_client_transaction *trans,
	const struct smtp_reply *reply);
void smtp_client_transaction_switch_ioloop(
	struct smtp_client_transaction *trans);

/*
 * Connection
 */

struct connection_list *smtp_client_connection_list_init(void);

const char *
smpt_client_connection_label(struct smtp_client_connection *conn);

void smtp_client_connection_fail(struct smtp_client_connection *conn,
				 unsigned int status, const char *error);

void smtp_client_connection_handle_output_error(
	struct smtp_client_connection *conn);
void smtp_client_connection_trigger_output(
	struct smtp_client_connection *conn);

void smtp_client_connection_start_cmd_timeout(
	struct smtp_client_connection *conn);
void smtp_client_connection_update_cmd_timeout(
	struct smtp_client_connection *conn);

void smtp_client_connection_add_transaction(
	struct smtp_client_connection *conn,
	struct smtp_client_transaction *trans);
void smtp_client_connection_abort_transaction(
	struct smtp_client_connection *conn,
	struct smtp_client_transaction *trans);
void smtp_client_connection_next_transaction(
	struct smtp_client_connection *conn,
	struct smtp_client_transaction *trans);

/*
 * Client
 */

int smtp_client_init_ssl_ctx(struct smtp_client *client, const char **error_r);

#endif
