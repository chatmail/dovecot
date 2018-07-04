/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"

#include "submission-commands.h"

/*
 * QUIT command
 */

struct cmd_quit_context {
	struct client *client;
	struct smtp_server_cmd_ctx *cmd;
	struct smtp_client_command *cmd_proxied;
};

static void cmd_quit_finish(struct cmd_quit_context *quit_cmd)
{
	struct client *client = quit_cmd->client;
	struct smtp_server_cmd_ctx *cmd = quit_cmd->cmd;

	timeout_remove(&client->to_quit);
	if (quit_cmd->cmd_proxied != NULL)
		smtp_client_command_abort(&quit_cmd->cmd_proxied);
	smtp_server_reply_quit(cmd);
}

static void cmd_quit_proxy_cb(
	const struct smtp_reply *proxy_reply ATTR_UNUSED,
	struct cmd_quit_context *quit_cmd)
{
	quit_cmd->cmd_proxied = NULL;
	cmd_quit_finish(quit_cmd);
}

static void cmd_quit_proxy(struct cmd_quit_context *quit_cmd)
{
	struct client *client = quit_cmd->client;
	struct smtp_server_cmd_ctx *cmd = quit_cmd->cmd;

	if (quit_cmd->cmd_proxied != NULL)
		return;

	if (smtp_client_connection_get_state(client->proxy_conn)
		< SMTP_CLIENT_CONNECTION_STATE_READY) {
		/* Don't bother proxying QUIT command when proxy is not
		   fully initialized. */
		smtp_server_reply_quit(cmd);
		return;
	}

	/* RFC 5321, Section 4.1.1.10:

	   The sender MUST NOT intentionally close the transmission channel
	   until it sends a QUIT command, and it SHOULD wait until it receives
	   the reply (even if there was an error response to a previous
	   command). */
	quit_cmd->cmd_proxied =
		smtp_client_command_new(client->proxy_conn, 0,
					cmd_quit_proxy_cb, quit_cmd);
	smtp_client_command_write(quit_cmd->cmd_proxied, "QUIT");
	smtp_client_command_submit(quit_cmd->cmd_proxied);
}

static void cmd_quit_next(struct smtp_server_cmd_ctx *cmd)
{
	struct cmd_quit_context *quit_cmd = cmd->context;
	struct client *client = quit_cmd->client;

	/* QUIT command is next to reply */

	cmd_quit_proxy(quit_cmd);

	if (quit_cmd->cmd_proxied != NULL) {
		/* give relay server brief interval to reply */
		client->to_quit = timeout_add(
			SUBMISSION_MAX_WAIT_QUIT_REPLY_MSECS,
			cmd_quit_finish, quit_cmd);
	}
}

int cmd_quit(void *conn_ctx, struct smtp_server_cmd_ctx *cmd)
{
	struct client *client = conn_ctx;
	struct cmd_quit_context *quit_cmd;

	quit_cmd = p_new(cmd->pool, struct cmd_quit_context, 1);
	quit_cmd->client = client;
	quit_cmd->cmd = cmd;

	cmd->hook_next = cmd_quit_next;
	cmd->context = quit_cmd;

	if (smtp_client_connection_get_state(client->proxy_conn)
		>= SMTP_CLIENT_CONNECTION_STATE_READY)
		cmd_quit_proxy(quit_cmd);
	return 0;
}
