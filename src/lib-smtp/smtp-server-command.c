/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "array.h"

#include "smtp-reply.h"
#include "smtp-server-private.h"

/*
 * Command registry
 */

void smtp_server_command_register(struct smtp_server *server,
	const char *name, smtp_server_cmd_start_func_t *func,
	enum smtp_server_command_flags flags)
{
	struct smtp_server_command_reg cmd;

	i_zero(&cmd);
	cmd.name = name;
	cmd.func = func;
	cmd.flags = flags;
	array_append(&server->commands_reg, &cmd, 1);

	server->commands_unsorted = TRUE;
}

void smtp_server_command_unregister(struct smtp_server *server,
				    const char *name)
{
	const struct smtp_server_command_reg *cmd;
	unsigned int i, count;

	cmd = array_get(&server->commands_reg, &count);
	for (i = 0; i < count; i++) {
		if (strcasecmp(cmd[i].name, name) == 0) {
			array_delete(&server->commands_reg, i, 1);
			return;
		}
	}

	i_panic("smtp-server: Trying to unregister unknown command '%s'", name);
}

static int
smtp_server_command_cmp(const struct smtp_server_command_reg *c1,
			const struct smtp_server_command_reg *c2)
{
	return strcasecmp(c1->name, c2->name);
}

static int
smtp_server_command_bsearch(const char *name,
			    const struct smtp_server_command_reg *cmd)
{
	return strcasecmp(name, cmd->name);
}

static struct smtp_server_command_reg *
smtp_server_command_find(struct smtp_server *server, const char *name)
{
	if (server->commands_unsorted) {
		array_sort(&server->commands_reg, smtp_server_command_cmp);
		server->commands_unsorted = FALSE;
	}

	return array_bsearch(&server->commands_reg,
		name, smtp_server_command_bsearch);
}

void smtp_server_commands_init(struct smtp_server *server)
{
	p_array_init(&server->commands_reg, server->pool, 16);

	switch (server->set.protocol) {
	case SMTP_PROTOCOL_SMTP:
		smtp_server_command_register(server,
			"EHLO", smtp_server_cmd_ehlo,
			SMTP_SERVER_CMD_FLAG_PRETLS |
			SMTP_SERVER_CMD_FLAG_PREAUTH);
		smtp_server_command_register(server,
			"HELO", smtp_server_cmd_helo,
			SMTP_SERVER_CMD_FLAG_PREAUTH);
		break;
	case SMTP_PROTOCOL_LMTP:
		smtp_server_command_register(server,
			"LHLO", smtp_server_cmd_ehlo,
			SMTP_SERVER_CMD_FLAG_PRETLS |
			SMTP_SERVER_CMD_FLAG_PREAUTH);
		break;
	}

	smtp_server_command_register(server,
		"AUTH", smtp_server_cmd_auth,
		SMTP_SERVER_CMD_FLAG_PREAUTH);
	smtp_server_command_register(server,
		"STARTTLS", smtp_server_cmd_starttls,
		SMTP_SERVER_CMD_FLAG_PRETLS | SMTP_SERVER_CMD_FLAG_PREAUTH);
	smtp_server_command_register(server,
		"MAIL", smtp_server_cmd_mail, 0);
	smtp_server_command_register(server,
		"RCPT", smtp_server_cmd_rcpt, 0);
	smtp_server_command_register(server,
		"DATA", smtp_server_cmd_data, 0);
	smtp_server_command_register(server,
		"BDAT", smtp_server_cmd_bdat, 0);
	smtp_server_command_register(server,
		"RSET", smtp_server_cmd_rset,
		SMTP_SERVER_CMD_FLAG_PREAUTH);
	smtp_server_command_register(server,
		"VRFY", smtp_server_cmd_vrfy, 0);
	smtp_server_command_register(server,
		"NOOP", smtp_server_cmd_noop,
		SMTP_SERVER_CMD_FLAG_PRETLS | SMTP_SERVER_CMD_FLAG_PREAUTH);
	smtp_server_command_register(server,
		"QUIT", smtp_server_cmd_quit,
		SMTP_SERVER_CMD_FLAG_PRETLS | SMTP_SERVER_CMD_FLAG_PREAUTH);

	smtp_server_command_register(server,
		"XCLIENT", smtp_server_cmd_xclient,
		SMTP_SERVER_CMD_FLAG_PREAUTH);
}

/*
 * Logging
 */

void smtp_server_command_debug(struct smtp_server_cmd_ctx *cmd,
			       const char *format, ...)
{
	struct smtp_server_connection *conn = cmd->conn;
	const struct smtp_server_settings *set = &conn->set;
	va_list args;

	if (set->debug) {
		va_start(args, format);
		i_debug("%s-server: conn %s: command %s: %s",
			smtp_protocol_name(set->protocol),
			smtp_server_connection_label(conn),
			smtp_server_command_label(cmd->cmd),
			t_strdup_vprintf(format, args));
		va_end(args);
	}
}

/*
 *
 */

struct smtp_server_command *
smtp_server_command_alloc(struct smtp_server_connection *conn)
{
	struct smtp_server_command *cmd;
	pool_t pool;

	pool = pool_alloconly_create("smtp_server_command", 256);
	cmd = p_new(pool, struct smtp_server_command, 1);
	cmd->context.pool = pool;
	cmd->context.cmd = cmd;
	cmd->refcount = 1;
	cmd->context.conn = conn;
	cmd->context.server = conn->server;
	cmd->replies_expected = 1;

	DLLIST2_APPEND(&conn->command_queue_head,
		       &conn->command_queue_tail, cmd);
	conn->command_queue_count++;

	return cmd;
}

struct smtp_server_command *
smtp_server_command_new(struct smtp_server_connection *conn,
			const char *name, const char *params)
{
	struct smtp_server *server = conn->server;
	const struct smtp_server_command_reg *cmd_reg;
	struct smtp_server_command *cmd;

	cmd = smtp_server_command_alloc(conn);
	cmd->context.name = p_strdup(cmd->context.pool, name);

	if ((cmd_reg=smtp_server_command_find(server, name)) == NULL) {
		/* RFC 5321, Section 4.2.4: Reply Code 502

		   Questions have been raised as to when reply code 502 (Command
		   not implemented) SHOULD be returned in preference to other
		   codes. 502 SHOULD be used when the command is actually
		   recognized by the SMTP server, but not implemented. If the
		   command is not recognized, code 500 SHOULD be returned.
		 */
		smtp_server_command_fail(cmd,
			500, "5.5.1", "Unknown command");

	} else if (!conn->ssl_secured && conn->set.tls_required &&
		(cmd_reg->flags & SMTP_SERVER_CMD_FLAG_PRETLS) == 0) {
		/* RFC 3207, Section 4:

		   A SMTP server that is not publicly referenced may choose to
		   require that the client perform a TLS negotiation before
		   accepting any commands. In this case, the server SHOULD
		   return the reply code:

		   530 Must issue a STARTTLS command first

		   to every command other than NOOP, EHLO, STARTTLS, or QUIT. If
		   the client and server are using the ENHANCEDSTATUSCODES ESMTP
		   extension [RFC2034], the status code to be returned SHOULD be
		   5.7.0.
		 */
		smtp_server_command_fail(cmd,
			530, "5.7.0", "TLS required.");

	} else if (!conn->authenticated && !conn->set.auth_optional &&
		(cmd_reg->flags & SMTP_SERVER_CMD_FLAG_PREAUTH) == 0) {
		/* RFC 4954, Section 6: Status Codes

		   530 5.7.0  Authentication required

		   This response SHOULD be returned by any command other than
		   AUTH, EHLO, HELO, NOOP, RSET, or QUIT when server policy
		   requires authentication in order to perform the requested
		   action and authentication is not currently in force.
		 */
		smtp_server_command_fail(cmd,
			530, "5.7.0", "Authentication required.");

	} else {
		struct smtp_server_command *tmp_cmd = cmd;

		i_assert(cmd_reg->func != NULL);
		smtp_server_command_ref(tmp_cmd);
		tmp_cmd->reg = cmd_reg;
		cmd_reg->func(&tmp_cmd->context, params);
		if (tmp_cmd->state == SMTP_SERVER_COMMAND_STATE_NEW)
			tmp_cmd->state = SMTP_SERVER_COMMAND_STATE_PROCESSING;
		if (!smtp_server_command_unref(&tmp_cmd))
			cmd = NULL;
	}
	return cmd;
}

void smtp_server_command_ref(struct smtp_server_command *cmd)
{
	cmd->refcount++;
}

bool smtp_server_command_unref(struct smtp_server_command **_cmd)
{
	struct smtp_server_command *cmd = *_cmd;
	struct smtp_server_connection *conn = cmd->context.conn;

	*_cmd = NULL;

	i_assert(cmd->refcount > 0);
	if (--cmd->refcount > 0)
		return TRUE;

	smtp_server_command_debug(&cmd->context, "Destroy");

	if (cmd->state < SMTP_SERVER_COMMAND_STATE_FINISHED) {
		cmd->state = SMTP_SERVER_COMMAND_STATE_ABORTED;
		DLLIST2_REMOVE(&conn->command_queue_head,
			&conn->command_queue_tail, cmd);
		conn->command_queue_count--;
	}

	/* execute hooks */
	if (cmd->context.hook_destroy != NULL)
		cmd->context.hook_destroy(&cmd->context);
	if (cmd->hook_destroy != NULL)
		cmd->hook_destroy(&cmd->context);

	smtp_server_reply_free(cmd);
	pool_unref(&cmd->context.pool);
	return FALSE;
}

void smtp_server_command_abort(struct smtp_server_command **_cmd)
{
	struct smtp_server_command *cmd = *_cmd;
	struct smtp_server_connection *conn = cmd->context.conn;

	/* preemptively remove command from queue (references may still exist)
	 */
	if (cmd->state < SMTP_SERVER_COMMAND_STATE_FINISHED) {
		cmd->state = SMTP_SERVER_COMMAND_STATE_ABORTED;
		DLLIST2_REMOVE(&conn->command_queue_head,
			&conn->command_queue_tail, cmd);
		conn->command_queue_count--;
	}
	smtp_server_reply_free(cmd);

	smtp_server_command_unref(_cmd);
}

void smtp_server_command_set_reply_count(struct smtp_server_command *cmd,
	unsigned int count)
{
	i_assert(count > 0);
	i_assert(!array_is_created(&cmd->replies));
	cmd->replies_expected = count;
}

void smtp_server_command_ready_to_reply(struct smtp_server_command *cmd)
{
	cmd->state = SMTP_SERVER_COMMAND_STATE_READY_TO_REPLY;
	smtp_server_command_debug(&cmd->context, "Ready to reply");
	smtp_server_connection_trigger_output(cmd->context.conn);
}

void smtp_server_command_next_to_reply(struct smtp_server_command *cmd)
{
	if (cmd->hook_next == NULL && cmd->context.hook_next == NULL)
		return;

	smtp_server_command_debug(&cmd->context, "Next to reply");

	/* execute private hook_next */
	if (cmd->hook_next != NULL) {
		smtp_server_cmd_func_t *hook_next = cmd->hook_next;

		cmd->hook_next = NULL;
		hook_next(&cmd->context);
	}

	/* execute public hook_next */
	if (cmd->context.hook_next != NULL) {
		smtp_server_cmd_func_t *hook_next = cmd->context.hook_next;

		cmd->context.hook_next = NULL;
		hook_next(&cmd->context);
	}
}

static void
smtp_server_command_replied(struct smtp_server_command *cmd)
{
	if (cmd->hook_replied == NULL && cmd->context.hook_replied == NULL)
		return;

	if (cmd->replies_submitted == cmd->replies_expected) {
		smtp_server_command_debug(&cmd->context, "Replied");

		/* execute private hook_replied */
		if (cmd->hook_replied != NULL) {
			smtp_server_cmd_func_t *hook_replied =
				cmd->hook_replied;

			cmd->hook_replied = NULL;
			hook_replied(&cmd->context);
		}

		/* execute public hook_replied */
		if (cmd->context.hook_replied != NULL) {
			smtp_server_cmd_func_t *hook_replied =
				cmd->context.hook_replied;

			cmd->context.hook_replied = NULL;
			hook_replied(&cmd->context);
		}
	}
}

void smtp_server_command_completed(struct smtp_server_command *cmd)
{
	if (cmd->hook_completed == NULL && cmd->context.hook_completed == NULL)
		return;

	if (cmd->replies_submitted == cmd->replies_expected) {
		smtp_server_command_debug(&cmd->context, "Completed");

		/* execute private hook_completed */
		if (cmd->hook_completed != NULL) {
			smtp_server_cmd_func_t *hook_completed =
				cmd->hook_completed;

			cmd->hook_completed = NULL;
			hook_completed(&cmd->context);
		}

		/* execute public hook_completed */
		if (cmd->context.hook_completed != NULL) {
			smtp_server_cmd_func_t *hook_completed =
				cmd->context.hook_completed;

			cmd->context.hook_completed = NULL;
			hook_completed(&cmd->context);
		}
	}
}

void smtp_server_command_submit_reply(struct smtp_server_command *cmd)
{
	struct smtp_server_connection *conn = cmd->context.conn;
	unsigned int i, submitted;
	bool is_bad = FALSE;

	i_assert(conn != NULL && array_is_created(&cmd->replies));

	submitted = 0;
	for (i = 0; i < cmd->replies_expected; i++) {
		const struct smtp_server_reply *reply =
			array_idx(&cmd->replies, i);
		if (!reply->submitted)
			continue;
		submitted++;

		i_assert(reply->content != NULL);
		switch (reply->content->status) {
		case 500:
		case 501:
		case 503:
			is_bad = TRUE;
			break;
		}
	}

	i_assert(submitted == cmd->replies_submitted);

	cmd->hook_next = NULL;
	cmd->context.hook_next = NULL;

	smtp_server_command_replied(cmd);

	/* limit number of consecutive bad commands */
	if (is_bad)
		conn->bad_counter++;
	else if (cmd->replies_submitted == cmd->replies_expected)
		conn->bad_counter = 0;

	/* submit reply */
	smtp_server_connection_ref(conn);
	switch (cmd->state) {
	case SMTP_SERVER_COMMAND_STATE_NEW:
	case SMTP_SERVER_COMMAND_STATE_PROCESSING:
		if (!smtp_server_command_is_complete(cmd)) {
			smtp_server_command_debug(&cmd->context,
				"Not ready to reply");
			cmd->state = SMTP_SERVER_COMMAND_STATE_SUBMITTED_REPLY;
			break;
		}
		smtp_server_command_ready_to_reply(cmd);
		break;
	case SMTP_SERVER_COMMAND_STATE_READY_TO_REPLY:
	case SMTP_SERVER_COMMAND_STATE_ABORTED:
		break;
	default:
		i_unreached();
	}
	if (!smtp_server_connection_unref(&conn))
		return;

	if (conn != NULL && conn->bad_counter > conn->set.max_bad_commands) {
		smtp_server_connection_terminate(&conn,
			"4.7.0", "Too many invalid commands.");
		return;
	}
}

bool smtp_server_command_is_replied(struct smtp_server_command *cmd)
{
	unsigned int i;

	if (!array_is_created(&cmd->replies))
		return FALSE;

	for (i = 0; i < cmd->replies_expected; i++) {
		const struct smtp_server_reply *reply =
			array_idx(&cmd->replies, i);
		if (!reply->submitted)
			return FALSE;
	}

	return TRUE;
}

struct smtp_server_reply *
smtp_server_command_get_reply(struct smtp_server_command *cmd,
	unsigned int idx)
{
	struct smtp_server_reply *reply;

	if (!array_is_created(&cmd->replies))
		return NULL;

	reply = array_idx_modifiable(&cmd->replies, idx);
	if (!reply->submitted)
		return NULL;
	return reply;
}

bool smtp_server_command_reply_status_equals(struct smtp_server_command *cmd,
	unsigned int status)
{
	struct smtp_server_reply *reply;

	i_assert(cmd->replies_expected == 1);
	reply = smtp_server_command_get_reply(cmd, 0);

	return (reply->content != NULL && reply->content->status == status);
}

bool smtp_server_command_replied_success(struct smtp_server_command *cmd)
{
	bool success = FALSE;
	unsigned int i;

	if (!array_is_created(&cmd->replies))
		return FALSE;

	for (i = 0; i < cmd->replies_expected; i++) {
		const struct smtp_server_reply *reply =
			array_idx(&cmd->replies, i);
		if (!reply->submitted)
			return FALSE;
		i_assert(reply->content != NULL);
		if (reply->content->status / 100 == 2)
			success = TRUE;
	}

	return success;
}

void smtp_server_command_finished(struct smtp_server_command *cmd)
{
	struct smtp_server_connection *conn = cmd->context.conn;
	struct smtp_server_reply *reply;

	i_assert(cmd->state < SMTP_SERVER_COMMAND_STATE_FINISHED);
	cmd->state = SMTP_SERVER_COMMAND_STATE_FINISHED;

	DLLIST2_REMOVE(&conn->command_queue_head,
		       &conn->command_queue_tail, cmd);
	conn->command_queue_count--;
	conn->stats.reply_count++;

	i_assert(array_is_created(&cmd->replies));
	reply = array_idx_modifiable(&cmd->replies, 0);
	i_assert(reply->content != NULL);

	if (reply->content->status == 221 || reply->content->status == 421) {
		i_assert(cmd->replies_expected == 1);
		if (reply->content->status == 421) {
			smtp_server_connection_close(&conn, t_strdup_printf(
				"Server closed the connection: %s",
				smtp_server_reply_get_one_line(reply)));

		} else {
			smtp_server_connection_close(&conn,
				"Client has quit the connection");
		}
		smtp_server_command_unref(&cmd);
		return;
	} else if (cmd->input_locked) {
		if (cmd->input_captured)
			smtp_server_connection_input_halt(conn);
		smtp_server_connection_input_resume(conn);
	}

	smtp_server_command_unref(&cmd);
	smtp_server_connection_trigger_output(conn);
}

void smtp_server_command_fail(struct smtp_server_command *cmd,
			      unsigned int status, const char *enh_code,
			      const char *fmt, ...)
{
	unsigned int i;
	va_list args;

	i_assert(status / 100 > 2);

	va_start(args, fmt);
	if (cmd->replies_expected == 1) {
		smtp_server_reply_indexv(&cmd->context, 0,
					 status, enh_code, fmt, args);
	} else for (i = 0; i < cmd->replies_expected; i++) {
		bool sent = FALSE;

		if (array_is_created(&cmd->replies)) {
			const struct smtp_server_reply *reply =
				array_idx(&cmd->replies, i);
			sent = reply->sent;
		}
	
		/* send the same reply for all */
		if (!sent) {
			va_list args_copy;
			VA_COPY(args_copy, args);
			smtp_server_reply_indexv(&cmd->context, i,
				status, enh_code, fmt, args_copy);
			va_end(args_copy);
		}
	}
	va_end(args);
}

void smtp_server_command_input_lock(struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_command *command = cmd->cmd;
	struct smtp_server_connection *conn = cmd->conn;

	command->input_locked = TRUE;
	smtp_server_connection_input_halt(conn);
}

void smtp_server_command_input_unlock(struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_command *command = cmd->cmd;
	struct smtp_server_connection *conn = cmd->conn;

	command->input_locked = FALSE;
	smtp_server_connection_input_resume(conn);
}

void smtp_server_command_input_capture(struct smtp_server_cmd_ctx *cmd,
	smtp_server_cmd_input_callback_t *callback)
{
	struct smtp_server_command *command = cmd->cmd;
	struct smtp_server_connection *conn = cmd->conn;

	smtp_server_connection_input_capture(conn, *callback, cmd);
	command->input_locked = TRUE;
	command->input_captured = TRUE;
}
