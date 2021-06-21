/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "array.h"
#include "safe-memset.h"
#include "ioloop.h"
#include "net.h"
#include "base64.h"
#include "istream.h"
#include "ostream.h"
#include "ostream-dot.h"
#include "iostream-rawlog.h"
#include "iostream-ssl.h"
#include "str.h"
#include "dsasl-client.h"
#include "dns-lookup.h"
#include "smtp-syntax.h"
#include "smtp-reply-parser.h"
#include "smtp-client-private.h"

#include <ctype.h>

const char *const smtp_client_connection_state_names[] = {
	"disconnected",
	"connecting",
	"handshaking",
	"authenticating",
	"ready",
	"transaction"
};

static int
smtp_client_connection_ssl_init(struct smtp_client_connection *conn,
				const char **error_r);
static void
smtp_client_connection_handshake(struct smtp_client_connection *conn);
static void
smtp_client_connection_established(struct smtp_client_connection *conn);
static void
smtp_client_connection_start_transaction(struct smtp_client_connection *conn);
static void
smtp_client_connection_connect_next_ip(struct smtp_client_connection *conn);
static bool
smtp_client_connection_last_ip(struct smtp_client_connection *conn);

/*
 * Capabilities
 */

enum smtp_capability
smtp_client_connection_get_capabilities(struct smtp_client_connection *conn)
{
	return conn->caps.standard;
}

uoff_t smtp_client_connection_get_size_capability(
	struct smtp_client_connection *conn)
{
	return conn->caps.size;
}

static const struct smtp_client_capability_extra *
smtp_client_connection_find_extra_capability(
	struct smtp_client_connection *conn, const char *cap_name)
{
	const struct smtp_client_capability_extra *cap;

	if (!array_is_created(&conn->extra_capabilities))
		return NULL;
	array_foreach(&conn->extra_capabilities, cap) {
		if (strcasecmp(cap->name, cap_name) == 0)
			return cap;
	}
	return NULL;
}

void smtp_client_connection_accept_extra_capability(
	struct smtp_client_connection *conn,
	const struct smtp_client_capability_extra *cap)
{
	i_assert(smtp_client_connection_find_extra_capability(conn, cap->name)
		 == NULL);
	
	if (!array_is_created(&conn->extra_capabilities))
		p_array_init(&conn->extra_capabilities, conn->pool, 8);

	struct smtp_client_capability_extra cap_new = {
		.name = p_strdup(conn->pool, cap->name),
	};

	if (cap->mail_param_extensions != NULL) {
		cap_new.mail_param_extensions =
			p_strarray_dup(conn->pool, cap->mail_param_extensions);
	}
	if (cap->rcpt_param_extensions != NULL) {
		cap_new.rcpt_param_extensions =
			p_strarray_dup(conn->pool, cap->rcpt_param_extensions);
	}

	array_push_back(&conn->extra_capabilities, &cap_new);
}

const struct smtp_capability_extra *
smtp_client_connection_get_extra_capability(struct smtp_client_connection *conn,
					    const char *name)
{
	const struct smtp_capability_extra *cap;

	if (!array_is_created(&conn->caps.extra))
		return NULL;

	array_foreach(&conn->caps.extra, cap) {
		if (strcasecmp(cap->name, name) == 0)
			return cap;
	}

	return NULL;
}

/*
 *
 */

static void
smtp_client_connection_commands_abort(struct smtp_client_connection *conn)
{
	smtp_client_commands_list_abort(conn->cmd_wait_list_head,
					conn->cmd_wait_list_count);
	smtp_client_commands_list_abort(conn->cmd_send_queue_head,
					conn->cmd_send_queue_count);
	smtp_client_commands_abort_delayed(conn);
}

static void
smtp_client_connection_commands_fail_reply(struct smtp_client_connection *conn,
					   const struct smtp_reply *reply)
{
	smtp_client_commands_list_fail_reply(conn->cmd_wait_list_head,
					     conn->cmd_wait_list_count, reply);
	smtp_client_commands_list_fail_reply(conn->cmd_send_queue_head,
					     conn->cmd_send_queue_count, reply);
	smtp_client_commands_fail_delayed(conn);
}

static void
smtp_client_connection_commands_fail(struct smtp_client_connection *conn,
				     unsigned int status, const char *error)
{
	struct smtp_reply reply;

	smtp_reply_init(&reply, status, error);
	reply.enhanced_code.x = 9;

	smtp_client_connection_commands_fail_reply(conn, &reply);
}

static void
smtp_client_connection_login_callback(struct smtp_client_connection *conn,
				      const struct smtp_reply *reply)
{
	const struct smtp_client_login_callback *cb;
	ARRAY(struct smtp_client_login_callback) login_cbs;

	if (conn->state_data.login_reply == NULL) {
		conn->state_data.login_reply =
			smtp_reply_clone(conn->state_pool, reply);
	}

	if (!array_is_created(&conn->login_callbacks) ||
	    array_count(&conn->login_callbacks) == 0)
		return;

	t_array_init(&login_cbs, array_count(&conn->login_callbacks));
	array_copy(&login_cbs.arr, 0, &conn->login_callbacks.arr, 0,
		   array_count(&conn->login_callbacks));
	array_foreach(&login_cbs, cb) {
		i_assert(cb->callback != NULL);
		if (conn->closed)
			break;
		if (cb->callback != NULL)
			cb->callback(reply, cb->context);
	}
	array_clear(&conn->login_callbacks);
}

static void
smtp_client_connection_login_fail(struct smtp_client_connection *conn,
				  unsigned int status, const char *error)
{
	struct smtp_reply reply;

	smtp_reply_init(&reply, status, error);
	reply.enhanced_code.x = 9;

	smtp_client_connection_login_callback(conn, &reply);
}

static void
smtp_client_connection_set_state(struct smtp_client_connection *conn,
				 enum smtp_client_connection_state state)
{
	conn->state = state;
}

void smtp_client_connection_cork(struct smtp_client_connection *conn)
{
	conn->corked = TRUE;
	if (conn->conn.output != NULL)
		o_stream_cork(conn->conn.output);
}

void smtp_client_connection_uncork(struct smtp_client_connection *conn)
{
	conn->corked = FALSE;
	if (conn->conn.output != NULL) {
		if (o_stream_uncork_flush(conn->conn.output) < 0) {
			smtp_client_connection_handle_output_error(conn);
			return;
		}
		smtp_client_connection_trigger_output(conn);
	}
}

enum smtp_client_connection_state
smtp_client_connection_get_state(struct smtp_client_connection *conn)
{
	return conn->state;
}

static void
smtp_client_command_timeout(struct smtp_client_connection *conn)
{
	smtp_client_connection_ref(conn);

	e_error(conn->event, "Command timed out, disconnecting");
	smtp_client_connection_fail(conn, SMTP_CLIENT_COMMAND_ERROR_TIMED_OUT,
				    "Command timed out");
	smtp_client_connection_unref(&conn);
}

void smtp_client_connection_start_cmd_timeout(
	struct smtp_client_connection *conn)
{
	unsigned int msecs = conn->set.command_timeout_msecs;

	if (conn->state < SMTP_CLIENT_CONNECTION_STATE_READY) {
		/* pre-login uses connect timeout */
		return;
	}
	if (msecs == 0) {
		/* no timeout configured */
		timeout_remove(&conn->to_commands);
		return;
	}
	if (conn->cmd_wait_list_head == NULL && !conn->sending_command) {
		/* no commands pending */
		timeout_remove(&conn->to_commands);
		return;
	}

	e_debug(conn->event, "Start timeout");
	if (conn->to_commands == NULL) {
		conn->to_commands = timeout_add(
			msecs, smtp_client_command_timeout, conn);
	}
}

void smtp_client_connection_update_cmd_timeout(
	struct smtp_client_connection *conn)
{
	unsigned int msecs = conn->set.command_timeout_msecs;

	if (conn->state < SMTP_CLIENT_CONNECTION_STATE_READY) {
		/* pre-login uses connect timeout */
		return;
	}
	if (msecs == 0) {
		/* no timeout configured */
		timeout_remove(&conn->to_commands);
		return;
	}

	if (conn->cmd_wait_list_head == NULL && !conn->sending_command) {
		if (conn->to_commands != NULL) {
			e_debug(conn->event,
				"No commands pending; stop timeout");
		}
		timeout_remove(&conn->to_commands);
	} else if (conn->to_commands != NULL)  {
		e_debug(conn->event, "Reset timeout");
		timeout_reset(conn->to_commands);
	} else {
		smtp_client_connection_start_cmd_timeout(conn);
	}
}

static void
smtp_client_connection_fail_reply(struct smtp_client_connection *conn,
				  const struct smtp_reply *reply)
{
	struct smtp_client_transaction *trans;

	e_debug(conn->event, "Connection failed: %s", smtp_reply_log(reply));

	smtp_client_connection_ref(conn);
	conn->failing = TRUE;

	smtp_client_connection_disconnect(conn);
	smtp_client_connection_login_callback(conn, reply);

	trans = conn->transactions_head;
	while (trans != NULL) {
		struct smtp_client_transaction *trans_next = trans->next;
		smtp_client_transaction_connection_result(trans, reply);
		trans = trans_next;
	}

	smtp_client_connection_commands_fail_reply(conn, reply);

	conn->failing = FALSE;
	smtp_client_connection_unref(&conn);
}

void smtp_client_connection_fail(struct smtp_client_connection *conn,
				 unsigned int status, const char *error)
{
	struct smtp_reply reply;
	const char *text_lines[] = {error, NULL};

	timeout_remove(&conn->to_connect);

	if (status == SMTP_CLIENT_COMMAND_ERROR_CONNECT_FAILED &&
	    !smtp_client_connection_last_ip(conn)) {
		conn->to_connect = timeout_add_short(
			0, smtp_client_connection_connect_next_ip, conn);
		return;
	}

	i_zero(&reply);
	reply.status = status;
	reply.text_lines = text_lines;
	reply.enhanced_code.x = 9;

	smtp_client_connection_fail_reply(conn, &reply);
}

static void
smtp_client_connection_lost(struct smtp_client_connection *conn,
			    const char *error, const char *user_error)
{
	if (error != NULL)
		error = t_strdup_printf("Connection lost: %s", error);

	if (user_error == NULL)
		user_error = "Lost connection to remote server";
	else {
		user_error = t_strdup_printf(
			"Lost connection to remote server: %s",
			user_error);
	}

	if (conn->ssl_iostream != NULL) {
		const char *sslerr =
			ssl_iostream_get_last_error(conn->ssl_iostream);

		if (error != NULL && sslerr != NULL) {
			error = t_strdup_printf("%s (last SSL error: %s)",
						error, sslerr);
		} else if (sslerr != NULL) {
			error = t_strdup_printf(
				"Connection lost (last SSL error: %s)", sslerr);
		}
		if (ssl_iostream_has_handshake_failed(conn->ssl_iostream)) {
			/* This isn't really a "connection lost", but that we
			   don't trust the remote's SSL certificate. */
			i_assert(error != NULL);
			e_error(conn->event, "%s", error);
			smtp_client_connection_fail(
				conn, SMTP_CLIENT_COMMAND_ERROR_CONNECT_FAILED,
				user_error);
			return;
		}
	}

	if (error != NULL)
		e_error(conn->event, "%s", error);
	smtp_client_connection_fail(
		conn, SMTP_CLIENT_COMMAND_ERROR_CONNECTION_LOST, user_error);
}

void smtp_client_connection_handle_output_error(
	struct smtp_client_connection *conn)
{
	struct ostream *output = conn->conn.output;

	if (output->stream_errno != EPIPE &&
	    output->stream_errno != ECONNRESET) {
		smtp_client_connection_lost(
			conn,
			t_strdup_printf("write(%s) failed: %s",
					o_stream_get_name(conn->conn.output),
					o_stream_get_error(conn->conn.output)),
			"Write failure");
	} else {
		smtp_client_connection_lost(
			conn, "Remote disconnected while writing output",
			"Remote closed connection unexpectedly");
	}
}

static void stmp_client_connection_ready(struct smtp_client_connection *conn,
					 const struct smtp_reply *reply)
{
	timeout_remove(&conn->to_connect);

	smtp_client_connection_set_state(
		conn, SMTP_CLIENT_CONNECTION_STATE_READY);
	conn->reset_needed = FALSE;

	e_debug(conn->event, "Connection ready");

	smtp_client_connection_login_callback(conn, reply);

	smtp_client_connection_update_cmd_timeout(conn);

	smtp_client_connection_start_transaction(conn);
}

static void
smtp_client_connection_xclient_cb(const struct smtp_reply *reply,
				  struct smtp_client_connection *conn)
{
	e_debug(conn->event, "Received XCLIENT handshake reply: %s",
		smtp_reply_log(reply));

	i_assert(conn->xclient_replies_expected > 0);

	if (reply->status == 421) {
		smtp_client_connection_fail_reply(conn, reply);
		return;
	}
	if (conn->state == SMTP_CLIENT_CONNECTION_STATE_DISCONNECTED)
		return;

	if (conn->to_connect != NULL)
		timeout_reset(conn->to_connect);
	if (--conn->xclient_replies_expected == 0)
		smtp_client_connection_handshake(conn);
}

static void
smtp_client_connection_xclient_submit(struct smtp_client_connection *conn,
				      const char *cmdstr)
{
	struct smtp_client_command *cmd;
	enum smtp_client_command_flags flags;

	e_debug(conn->event, "Sending XCLIENT handshake");

	flags = SMTP_CLIENT_COMMAND_FLAG_PRELOGIN |
		SMTP_CLIENT_COMMAND_FLAG_PRIORITY;

	cmd = smtp_client_command_new(conn, flags,
				      smtp_client_connection_xclient_cb, conn);
	smtp_client_command_write(cmd, cmdstr);
	smtp_client_command_submit(cmd);

	conn->xclient_replies_expected++;
}

static void
smtp_client_connection_xclient_add(struct smtp_client_connection *conn,
				   string_t *str, size_t offset,
				   const char *field, const char *value)
{
	size_t prev_offset = str_len(str);
	const char *new_field;

	i_assert(prev_offset >= offset);

	str_append_c(str, ' ');
	str_append(str, field);
	str_append_c(str, '=');
	smtp_xtext_encode_cstr(str, value);

	if (prev_offset == offset ||
	    str_len(str) <= SMTP_CLIENT_BASE_LINE_LENGTH_LIMIT)
		return;
		
	/* preserve field we just added */
	new_field = t_strdup(str_c(str) + prev_offset);

	/* revert to previous position */
	str_truncate(str, prev_offset);

	/* send XCLIENT command */
	smtp_client_connection_xclient_submit(conn, str_c(str));

	/* start next XCLIENT command with new field */
	str_truncate(str, offset);
	str_append(str, new_field);
}

static void ATTR_FORMAT(5, 6)
smtp_client_connection_xclient_addf(struct smtp_client_connection *conn,
				    string_t *str, size_t offset,
				    const char *field, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	smtp_client_connection_xclient_add(conn, str, offset, field,
					   t_strdup_vprintf(format, args));
	va_end(args);
}

void smtp_client_connection_send_xclient(struct smtp_client_connection *conn)
{
	const struct smtp_proxy_data *xclient = &conn->set.proxy_data;
	const char **xclient_args = conn->caps.xclient_args;
	size_t offset;
	string_t *str;

	if (!conn->set.peer_trusted)
		return;
	if (conn->xclient_sent)
		return;
	if ((conn->caps.standard & SMTP_CAPABILITY_XCLIENT) == 0 ||
	    conn->caps.xclient_args == NULL)
		return;

	i_assert(conn->xclient_replies_expected == 0);

	/* http://www.postfix.org/XCLIENT_README.html:

	   The client must not send XCLIENT commands that exceed the 512
	   character limit for SMTP commands. To avoid exceeding the limit the
	   client should send the information in multiple XCLIENT commands; for
	   example, send NAME and ADDR last, after HELO and PROTO. Once ADDR is
	   sent, the client is usually no longer authorized to send XCLIENT
	   commands.
	 */

	str = t_str_new(64);
	str_append(str, "XCLIENT");
	offset = str_len(str);

	/* HELO */
	if (xclient->helo != NULL &&
	    str_array_icase_find(xclient_args, "HELO")) {
		smtp_client_connection_xclient_add(conn, str, offset,
						   "HELO", xclient->helo);
	}

	/* PROTO */
	if (str_array_icase_find(xclient_args, "PROTO")) {
		switch (xclient->proto) {
		case SMTP_PROXY_PROTOCOL_SMTP:
			smtp_client_connection_xclient_add(conn, str, offset,
							   "PROTO", "SMTP");
			break;
		case SMTP_PROXY_PROTOCOL_ESMTP:
			smtp_client_connection_xclient_add(conn, str, offset,
							   "PROTO", "ESMTP");
			break;
		case SMTP_PROXY_PROTOCOL_LMTP:
			smtp_client_connection_xclient_add(conn, str, offset,
							   "PROTO", "LMTP");
			break;
		default:
			break;
		}
	}

	/* LOGIN */
	if (xclient->login != NULL &&
	    str_array_icase_find(xclient_args, "LOGIN")) {
		smtp_client_connection_xclient_add(conn, str, offset,
						   "LOGIN", xclient->login);
	}

	/* TTL */
	if (xclient->ttl_plus_1 > 0 &&
	    str_array_icase_find(xclient_args, "TTL")) {
		smtp_client_connection_xclient_addf(conn, str, offset,
						    "TTL", "%u",
						    xclient->ttl_plus_1-1);
	}

	/* TIMEOUT */
	if (xclient->timeout_secs > 0 &&
	    str_array_icase_find(xclient_args, "TIMEOUT")) {
		smtp_client_connection_xclient_addf(conn, str, offset,
						    "TIMEOUT", "%u",
						    xclient->timeout_secs);
	}

	/* PORT */
	if (xclient->source_port != 0 &&
	    str_array_icase_find(xclient_args, "PORT")) {
		smtp_client_connection_xclient_addf(conn, str, offset,
						    "PORT", "%u",
						    xclient->source_port);
	}

	/* ADDR */
	if (xclient->source_ip.family != 0 &&
	    str_array_icase_find(xclient_args, "ADDR")) {
		const char *addr = net_ip2addr(&xclient->source_ip);

		/* Older versions of Dovecot LMTP don't quite follow Postfix'
		   specification of the XCLIENT command regarding IPv6
		   addresses: the "IPV6:" prefix is omitted. For now, we
		   maintain this deviation for LMTP. Newer versions of Dovecot
		   LMTP can work with or without the prefix. */
		if (conn->protocol != SMTP_PROTOCOL_LMTP &&
			xclient->source_ip.family == AF_INET6)
			addr = t_strconcat("IPV6:", addr, NULL);
		smtp_client_connection_xclient_add(conn, str, offset,
						   "ADDR", addr);
	}

	/* final XCLIENT command */
	if (str_len(str) > offset)
		smtp_client_connection_xclient_submit(conn, str_c(str));

	conn->xclient_sent = TRUE;
}

static void
smtp_client_connection_clear_password(struct smtp_client_connection *conn)
{
	if (conn->set.remember_password)
		return;
	if (conn->password == NULL)
		return;
	safe_memset(conn->password, 0, strlen(conn->password));
	conn->set.password = NULL;
	conn->password = NULL;
}

static void
smtp_client_connection_auth_cb(const struct smtp_reply *reply,
			       struct smtp_client_connection *conn)
{
	if (reply->status == 334) {
		const unsigned char *sasl_output;
		size_t sasl_output_len, input_len;
		buffer_t *buf;
		const char *error;

		if (reply->text_lines[1] != NULL) {
			e_error(conn->event, "Authentication failed: "
				"Server returned multi-line reply: %s",
				smtp_reply_log(reply));
			smtp_client_connection_fail(
				conn, SMTP_CLIENT_COMMAND_ERROR_AUTH_FAILED,
				"Authentication protocol error");
			return;
		}

		input_len = strlen(reply->text_lines[0]);
		buf = buffer_create_dynamic(pool_datastack_create(),
			MAX_BASE64_DECODED_SIZE(input_len));
		if (base64_decode(reply->text_lines[0], input_len,
				  NULL, buf) < 0) {
			e_error(conn->event, "Authentication failed: "
				"Server sent non-base64 input for AUTH: %s",
				reply->text_lines[0]);
		} else if (dsasl_client_input(conn->sasl_client,
					      buf->data, buf->used,
					      &error) < 0) {
			e_error(conn->event, "Authentication failed: %s",
				error);
		} else if (dsasl_client_output(conn->sasl_client, &sasl_output,
					       &sasl_output_len, &error) < 0) {
			e_error(conn->event, "Authentication failed: %s",
				error);
		} else {
			string_t *smtp_output = t_str_new(
				MAX_BASE64_ENCODED_SIZE(sasl_output_len) + 2);
			base64_encode(sasl_output, sasl_output_len,
				      smtp_output);
			str_append(smtp_output, "\r\n");
			o_stream_nsend(conn->conn.output, str_data(smtp_output),
				       str_len(smtp_output));
			return;
		}

		smtp_client_connection_fail(
			conn, SMTP_CLIENT_COMMAND_ERROR_AUTH_FAILED,
			"Authentication failed");
		return;
	}

	if ((reply->status / 100) != 2) {
		e_error(conn->event, "Authentication failed: %s",
			smtp_reply_log(reply));
		smtp_client_connection_fail_reply(conn, reply);
		return;
	}

	smtp_client_connection_clear_password(conn);

	e_debug(conn->event, "Authenticated successfully");
	dsasl_client_free(&conn->sasl_client);

	if (conn->to_connect != NULL)
		timeout_reset(conn->to_connect);
	conn->authenticated = TRUE;
	smtp_client_connection_handshake(conn);
}

static int
smtp_client_connection_get_sasl_mech(struct smtp_client_connection *conn,
				     const struct dsasl_client_mech **mech_r,
				     const char **error_r)
{
	const struct smtp_client_settings *set = &conn->set;
	const char *const *mechanisms;

	if (set->sasl_mech != NULL) {
		const char *mech = dsasl_client_mech_get_name(set->sasl_mech);

		if (!str_array_icase_find(conn->caps.auth_mechanisms, mech)) {
			*error_r = t_strdup_printf(
				"Server doesn't support `%s' SASL mechanism",
				mech);
			return -1;
		}
		*mech_r = set->sasl_mech;
		return 0;
	}
	if (set->sasl_mechanisms == NULL ||
		set->sasl_mechanisms[0] == '\0') {
		*mech_r = &dsasl_client_mech_plain;
		return 0;
	}		

	/* find one of the specified SASL mechanisms */
	mechanisms = t_strsplit_spaces(set->sasl_mechanisms, ", ");
	for (; *mechanisms != NULL; mechanisms++) {
		if (str_array_icase_find(conn->caps.auth_mechanisms,
					 *mechanisms)) {
			*mech_r = dsasl_client_mech_find(*mechanisms);
			if (*mech_r != NULL)
				return 0;

			*error_r = t_strdup_printf(
				"Support for SASL mechanism `%s' is missing",
				*mechanisms);
			return -1;
		}
	}
	*error_r = t_strdup_printf(
		"Server doesn't support any of "
		"the requested SASL mechanisms: %s", set->sasl_mechanisms);
	return -1;
}

static bool
smtp_client_connection_authenticate(struct smtp_client_connection *conn)
{
	const struct smtp_client_settings *set = &conn->set;
	struct dsasl_client_settings sasl_set;
	const struct dsasl_client_mech *sasl_mech = NULL;
	struct smtp_client_command *cmd;
	const unsigned char *sasl_output;
	size_t sasl_output_len;
	string_t *sasl_output_base64;
	const char *init_resp, *error;

	if (set->username == NULL && set->sasl_mech == NULL) {
		if (!conn->set.xclient_defer)
			smtp_client_connection_send_xclient(conn);
		return (conn->xclient_replies_expected == 0);
	}

	smtp_client_connection_send_xclient(conn);
	if (conn->xclient_replies_expected > 0)
		return FALSE;
	if (conn->authenticated)
		return TRUE;

	if ((conn->caps.standard & SMTP_CAPABILITY_AUTH) == 0) {
		smtp_client_connection_fail(
			conn, SMTP_CLIENT_COMMAND_ERROR_AUTH_FAILED,
			"Authentication not supported");
		return FALSE;
	}

	if (set->master_user != NULL) {
		e_debug(conn->event, "Authenticating as %s for user %s",
			set->master_user, set->username);
	} else if (set->username == NULL) {
		e_debug(conn->event, "Authenticating");
	} else {
		e_debug(conn->event, "Authenticating as %s", set->username);
	}

	if (smtp_client_connection_get_sasl_mech(conn, &sasl_mech,
						 &error) < 0) {
		e_error(conn->event, "Authentication failed: %s", error);
		smtp_client_connection_fail(
			conn, SMTP_CLIENT_COMMAND_ERROR_AUTH_FAILED,
			"Server authentication mechanisms incompatible");
		return FALSE;
	}

	i_zero(&sasl_set);
	if (set->master_user == NULL)
		sasl_set.authid = set->username;
	else {
		sasl_set.authid = set->master_user;
		sasl_set.authzid = set->username;
	}
	sasl_set.password = set->password;

	conn->sasl_client = dsasl_client_new(sasl_mech, &sasl_set);

	if (dsasl_client_output(conn->sasl_client, &sasl_output,
				&sasl_output_len, &error) < 0) {
		e_error(conn->event,
			"Failed to create initial %s SASL reply: %s",
			dsasl_client_mech_get_name(sasl_mech), error);
		smtp_client_connection_fail(
			conn, SMTP_CLIENT_COMMAND_ERROR_AUTH_FAILED,
			"Internal authentication failure");
		return FALSE;
	}

	sasl_output_base64 = t_str_new(
		MAX_BASE64_ENCODED_SIZE(sasl_output_len));
	base64_encode(sasl_output, sasl_output_len, sasl_output_base64);

	/* RFC 4954, Section 4:

	   If the client is transmitting an initial response of zero
	   length, it MUST instead transmit the response as a single
	   equals sign ("=").  This indicates that the response is
	   present, but contains no data. */
	init_resp = (str_len(sasl_output_base64) == 0 ?
		     "=" : str_c(sasl_output_base64));

	cmd = smtp_client_command_new(conn, SMTP_CLIENT_COMMAND_FLAG_PRELOGIN,
				      smtp_client_connection_auth_cb, conn);
	smtp_client_command_printf(cmd, "AUTH %s %s",
				   dsasl_client_mech_get_name(sasl_mech),
				   init_resp);
	smtp_client_command_submit(cmd);

	smtp_client_connection_set_state(
		conn, SMTP_CLIENT_CONNECTION_STATE_AUTHENTICATING);
	return FALSE;
}

static void
smtp_client_connection_starttls_cb(const struct smtp_reply *reply,
				   struct smtp_client_connection *conn)
{
	const char *error;

	e_debug(conn->event, "Received STARTTLS reply: %s",
		smtp_reply_log(reply));

	if ((reply->status / 100) != 2) {
		smtp_client_connection_fail_reply(conn, reply);
		return;
	}

	if (smtp_client_connection_ssl_init(conn, &error) < 0) {
		smtp_client_connection_fail(
			conn, SMTP_CLIENT_COMMAND_ERROR_CONNECT_FAILED, error);
	} else {
		if (conn->to_connect != NULL)
			timeout_reset(conn->to_connect);
		smtp_client_connection_handshake(conn);
	}
}

static bool
smtp_client_connection_starttls(struct smtp_client_connection *conn)
{
	struct smtp_client_command *cmd;

	if (conn->ssl_mode == SMTP_CLIENT_SSL_MODE_STARTTLS &&
	    conn->ssl_iostream == NULL) {
		if ((conn->caps.standard & SMTP_CAPABILITY_STARTTLS) == 0) {
			e_error(conn->event, "Requested STARTTLS, "
				"but server doesn't support it");
			smtp_client_connection_fail(
				conn, SMTP_CLIENT_COMMAND_ERROR_CONNECT_FAILED,
				"STARTTLS not supported");
			return FALSE;
		}

		e_debug(conn->event, "Starting TLS");

		cmd = smtp_client_command_new(
			conn, SMTP_CLIENT_COMMAND_FLAG_PRELOGIN,
			smtp_client_connection_starttls_cb, conn);
		smtp_client_command_write(cmd, "STARTTLS");
		smtp_client_command_submit(cmd);
		return FALSE;
	}

	return smtp_client_connection_authenticate(conn);
}

static void
smtp_client_connection_record_param_extensions(
	struct smtp_client_connection *conn, ARRAY_TYPE(const_string) *arr,
	const char *const *extensions)
{
	pool_t pool = conn->cap_pool;

	if (extensions == NULL || *extensions == NULL)
		return;

	if (!array_is_created(arr))
		p_array_init(arr, pool, 4);
	else {
		const char *const *end;

		/* Drop end marker */
		i_assert(array_count(arr) > 0);
		end = array_back(arr);
		i_assert(*end == NULL);
		array_pop_back(arr);
	}

	const char *const *new_p;
	for (new_p = extensions; *new_p != NULL; new_p++) {
		/* Drop duplicates */
		if (array_lsearch(arr, new_p, i_strcasecmp_p) != NULL)
			continue;

		array_push_back(arr, new_p);
	}

	/* Add new end marker */
	array_append_zero(arr);
}

static void
smtp_client_connection_record_extra_capability(
	struct smtp_client_connection *conn, const char *cap_name,
	const char *const *params)
{
	const struct smtp_client_capability_extra *ccap_extra;
	struct smtp_capability_extra cap_extra;
	pool_t pool = conn->cap_pool;

	ccap_extra = smtp_client_connection_find_extra_capability(
		conn, cap_name);
	if (ccap_extra == NULL)
		return;
	if (smtp_client_connection_get_extra_capability(conn, cap_name) != NULL)
		return;

	if (!array_is_created(&conn->caps.extra))
		p_array_init(&conn->caps.extra, pool, 4);

	i_zero(&cap_extra);
	cap_extra.name = p_strdup(pool, ccap_extra->name);
	cap_extra.params = p_strarray_dup(pool, params);

	array_push_back(&conn->caps.extra, &cap_extra);

	smtp_client_connection_record_param_extensions(
		conn, &conn->caps.mail_param_extensions,
		ccap_extra->mail_param_extensions);
	smtp_client_connection_record_param_extensions(
		conn, &conn->caps.rcpt_param_extensions,
		ccap_extra->rcpt_param_extensions);
}

static void
smtp_client_connection_handshake_cb(const struct smtp_reply *reply,
				    struct smtp_client_connection *conn)
{
	const char *const *lines;

	e_debug(conn->event, "Received handshake reply");

	/* check reply status */
	if ((reply->status / 100) != 2) {
		/* RFC 5321, Section 3.2:
		   For a particular connection attempt, if the server returns a
		   "command not recognized" response to EHLO, the client SHOULD
		   be able to fall back and send HELO. */
		if (conn->protocol == SMTP_PROTOCOL_SMTP && !conn->old_smtp &&
		    (reply->status == 500 || reply->status == 502)) {
			/* try HELO */
			conn->old_smtp = TRUE;
			smtp_client_connection_handshake(conn);
			return;
		}
		/* failed */
		smtp_client_connection_fail_reply(conn, reply);
		return;
	}

	/* reset capabilities */
	p_clear(conn->cap_pool);
	i_zero(&conn->caps);
	conn->caps.standard = conn->set.forced_capabilities;

	lines = reply->text_lines;
	if (*lines == NULL) {
		smtp_client_connection_fail(
			conn, SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY,
			"Invalid handshake reply");
		return;
	}

	/* greeting line */
	lines++;

	/* capability lines */
	while (*lines != NULL) {
		enum smtp_capability cap;
		const char *const *params;
		const char *cap_name, *error;

		if (smtp_ehlo_line_parse(*lines, &cap_name, &params,
					 &error) <= 0) {
			e_warning(conn->event,
				  "Received invalid EHLO response line: %s",
				  error);
			lines++;
			continue;
		}

		cap = smtp_capability_find_by_name(cap_name);
		switch (cap) {
		case SMTP_CAPABILITY_AUTH:
			conn->caps.auth_mechanisms =
				p_strarray_dup(conn->cap_pool, params);
			break;
		case SMTP_CAPABILITY_SIZE:
			if (params == NULL || *params == NULL)
				break;
			if (str_to_uoff(*params, &conn->caps.size) < 0) {
				e_warning(conn->event,
					  "Received invalid SIZE capability "
					  "in EHLO response line");
				cap = SMTP_CAPABILITY_NONE;
			}
			break;
		case SMTP_CAPABILITY_XCLIENT:
			conn->caps.xclient_args =
				p_strarray_dup(conn->cap_pool, params);
			break;
		case SMTP_CAPABILITY_NONE:
			smtp_client_connection_record_extra_capability(
				conn, cap_name, params);
			break;
		default:
			break;
		}

		conn->caps.standard |= cap;
		lines++;
	}

	e_debug(conn->event, "Received server capabilities");

	if (conn->to_connect != NULL)
		timeout_reset(conn->to_connect);
	if (smtp_client_connection_starttls(conn)) {
		stmp_client_connection_ready(conn, reply);
	}
}

static void
smtp_client_connection_handshake(struct smtp_client_connection *conn)
{
	struct smtp_client_command *cmd;
	enum smtp_client_command_flags flags;
	const char *command;

	flags = SMTP_CLIENT_COMMAND_FLAG_PRELOGIN |
		SMTP_CLIENT_COMMAND_FLAG_PRIORITY;

	switch (conn->protocol) {
	case SMTP_PROTOCOL_SMTP:
		command = (conn->old_smtp ? "HELO" : "EHLO");
		break;
	case SMTP_PROTOCOL_LMTP:
		command = "LHLO";
		break;
	default:
		i_unreached();
	}

	e_debug(conn->event, "Sending %s handshake", command);

	cmd = smtp_client_command_new(
		conn, flags, smtp_client_connection_handshake_cb, conn);
	smtp_client_command_write(cmd, command);
	smtp_client_command_write(cmd, " ");
	smtp_client_command_write(cmd, conn->set.my_hostname);
	smtp_client_command_submit(cmd);
	smtp_client_connection_set_state(
		conn, SMTP_CLIENT_CONNECTION_STATE_HANDSHAKING);
}

static int
smtp_client_connection_input_reply(struct smtp_client_connection *conn,
				   const struct smtp_reply *reply)
{
	int ret;

	/* initial greeting? */
	if (conn->state == SMTP_CLIENT_CONNECTION_STATE_CONNECTING) {
		e_debug(conn->event, "Received greeting from server: %s",
			smtp_reply_log(reply));
		if (reply->status != 220) {
			if (smtp_reply_is_success(reply)) {
				smtp_client_connection_fail(
					conn,
					SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY,
					"Received inappropriate greeting");
			} else {
				smtp_client_connection_fail_reply(conn, reply);
			}
			return -1;
		}
		smtp_client_connection_handshake(conn);
		return 1;
	}

	if (reply->status == SMTP_CLIENT_COMMAND_ERROR_CONNECTION_CLOSED) {
		smtp_client_connection_fail_reply(conn, reply);
		return -1;
	}

	/* unexpected reply? */
	if (conn->cmd_wait_list_head == NULL) {
		e_debug(conn->event, "Unexpected reply: %s",
			smtp_reply_log(reply));
		smtp_client_connection_fail(
			conn, SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY,
			"Got unexpected reply");
		return -1;
	}

	/* replied early? */
	if (conn->cmd_wait_list_head == conn->cmd_streaming &&
	    !conn->cmd_wait_list_head->stream_finished) {
		e_debug(conn->event, "Early reply: %s", smtp_reply_log(reply));
		if (smtp_reply_is_success(reply)) {
			smtp_client_connection_fail(
				conn, SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY,
				"Got early success reply");
			return -1;
		}
	}

	/* command reply */
	ret = smtp_client_command_input_reply(conn->cmd_wait_list_head, reply);

	if (conn->state == SMTP_CLIENT_CONNECTION_STATE_DISCONNECTED ||
	    conn->conn.output == NULL)
		return -1;
	return ret;
}

static void smtp_client_connection_input(struct connection *_conn)
{
	struct smtp_client_connection *conn =
		(struct smtp_client_connection *)_conn;
	bool enhanced_codes = ((conn->caps.standard &
				SMTP_CAPABILITY_ENHANCEDSTATUSCODES) != 0);
	struct smtp_reply *reply;
	const char *error = NULL;
	int ret;

	if (conn->ssl_iostream != NULL &&
	    !ssl_iostream_is_handshaked(conn->ssl_iostream)) {
		/* finish SSL negotiation by reading from input stream */
		while ((ret = i_stream_read(conn->conn.input)) > 0 ||
		       ret == -2) {
			if (ssl_iostream_is_handshaked(conn->ssl_iostream))
				break;
		}
		if (ret < 0) {
			/* failed somehow */
			i_assert(ret != -2);
			e_error(conn->event,
				"SSL handshaking with %s failed: "
				"read(%s) failed: %s", _conn->name,
				i_stream_get_name(conn->conn.input),
				i_stream_get_error(conn->conn.input));
			smtp_client_connection_fail(
				conn, SMTP_CLIENT_COMMAND_ERROR_CONNECT_FAILED,
				"Failed to connect to remote server");
			return;
		}

		if (!ssl_iostream_is_handshaked(conn->ssl_iostream)) {
			/* not finished */
			i_assert(ret == 0);
			return;
		}

		if (conn->to_connect != NULL)
			timeout_reset(conn->to_connect);
	}

	if (!conn->connect_succeeded) {
		/* just got ready for SMTP handshake */
		smtp_client_connection_established(conn);
	}

	smtp_client_connection_ref(conn);
	o_stream_cork(conn->conn.output);
	for (;;) {
		if (conn->cmd_wait_list_head != NULL &&
		    conn->cmd_wait_list_head->ehlo) {
			if ((ret = smtp_reply_parse_ehlo(conn->reply_parser,
							 &reply, &error)) <= 0)
				break;
		} else {
			if ((ret = smtp_reply_parse_next(conn->reply_parser,
							 enhanced_codes,
							 &reply, &error)) <= 0)
				break;
		}

		T_BEGIN {
			ret = smtp_client_connection_input_reply(conn, reply);
		} T_END;
		if (ret < 0) {
			if (conn->conn.output != NULL && !conn->corked)
				o_stream_uncork(conn->conn.output);
			smtp_client_connection_unref(&conn);
			return;
		}
	}

	if (ret < 0 || (ret == 0 && conn->conn.input->eof)) {
		if (conn->conn.input->stream_errno == ENOBUFS) {
			smtp_client_connection_fail(
				conn, SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY,
				"Command reply line too long");
		} else if (conn->conn.input->stream_errno != 0) {
			smtp_client_connection_lost(
				conn,
				t_strdup_printf(
					"read(%s) failed: %s",
					i_stream_get_name(conn->conn.input),
					i_stream_get_error(conn->conn.input)),
				"Read failure");
		} else if (!i_stream_have_bytes_left(conn->conn.input)) {
			if (conn->sent_quit) {
				smtp_client_connection_lost(
					conn, NULL,
					"Remote closed connection");
			} else {
				smtp_client_connection_lost(
					conn, NULL,
					"Remote closed connection unexpectedly");
			}
		} else {
			i_assert(error != NULL);
			smtp_client_connection_fail(
				conn, SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY,
				t_strdup_printf("Invalid command reply: %s",
						error));
		}
	}
	if (ret >= 0 && conn->conn.output != NULL && !conn->corked) {
		if (o_stream_uncork_flush(conn->conn.output) < 0)
			smtp_client_connection_handle_output_error(conn);
	}
	smtp_client_connection_unref(&conn);
}

static int smtp_client_connection_output(struct smtp_client_connection *conn)
{
	int ret;

	if (conn->to_connect != NULL)
		timeout_reset(conn->to_connect);

	ret = o_stream_flush(conn->conn.output);
	if (ret <= 0) {
		if (ret < 0)
			smtp_client_connection_handle_output_error(conn);
		return ret;
	}

	smtp_client_connection_ref(conn);
	o_stream_cork(conn->conn.output);
	if (smtp_client_command_send_more(conn) < 0)
		ret = -1;
	if (ret >= 0 && conn->conn.output != NULL && !conn->corked) {
		if (o_stream_uncork_flush(conn->conn.output) < 0)
			smtp_client_connection_handle_output_error(conn);
	}
	smtp_client_connection_unref(&conn);
	return ret;
}

void smtp_client_connection_trigger_output(struct smtp_client_connection *conn)
{
	if (conn->conn.output != NULL)
		o_stream_set_flush_pending(conn->conn.output, TRUE);
}

static void smtp_client_connection_destroy(struct connection *_conn)
{
	struct smtp_client_connection *conn =
		(struct smtp_client_connection *)_conn;

	switch (_conn->disconnect_reason) {
	case CONNECTION_DISCONNECT_NOT:
		break;
	case CONNECTION_DISCONNECT_DEINIT:
		e_debug(conn->event, "Connection deinit");
		smtp_client_connection_commands_abort(conn);
		smtp_client_connection_close(&conn);
		break;
	case CONNECTION_DISCONNECT_CONNECT_TIMEOUT:
		e_error(conn->event, "connect(%s) failed: Connection timed out",
			_conn->name);
		smtp_client_connection_fail(
			conn, SMTP_CLIENT_COMMAND_ERROR_CONNECT_FAILED,
			"Connect timed out");
		break;
	default:
	case CONNECTION_DISCONNECT_CONN_CLOSED:
		if (conn->connect_failed) {
			smtp_client_connection_fail(conn,
				SMTP_CLIENT_COMMAND_ERROR_CONNECT_FAILED,
				"Failed to connect to remote server");
			break;
		}
		if (_conn->input != NULL && _conn->input->stream_errno != 0) {
			smtp_client_connection_lost(
				conn,
				t_strdup_printf("read(%s) failed: %s",
					i_stream_get_name(conn->conn.input),
					i_stream_get_error(conn->conn.input)),
				"Read failure");
			break;
		}
		smtp_client_connection_lost(
			conn, "Remote disconnected",
			"Remote closed connection unexpectedly");
		break;
	}
}

static void
smtp_client_connection_established(struct smtp_client_connection *conn)
{
	i_assert(!conn->connect_succeeded);
	conn->connect_succeeded = TRUE;

	if (conn->to_connect != NULL)
		timeout_reset(conn->to_connect);

	/* set flush callback */
	o_stream_set_flush_callback(conn->conn.output,
		smtp_client_connection_output, conn);
}

static int
smtp_client_connection_ssl_handshaked(const char **error_r, void *context)
{
	struct smtp_client_connection *conn = context;
	const char *error, *host = conn->host;

	if (ssl_iostream_check_cert_validity(conn->ssl_iostream,
					     host, &error) == 0) {
		e_debug(conn->event, "SSL handshake successful");
	} else if (conn->set.ssl->allow_invalid_cert) {
		e_debug(conn->event, "SSL handshake successful, "
			"ignoring invalid certificate: %s", error);
	} else {
		*error_r = error;
		return -1;
	}
	return 0;
}

static void
smtp_client_connection_streams_changed(struct smtp_client_connection *conn)
{
	struct stat st;

	if (conn->set.rawlog_dir != NULL &&
	    stat(conn->set.rawlog_dir, &st) == 0) {
		iostream_rawlog_create(conn->set.rawlog_dir,
				       &conn->conn.input, &conn->conn.output);
	}

	if (conn->reply_parser == NULL) {
		conn->reply_parser = smtp_reply_parser_init(
			conn->conn.input, conn->set.max_reply_size);
	} else {
		smtp_reply_parser_set_stream(conn->reply_parser,
					     conn->conn.input);
	}

	connection_streams_changed(&conn->conn);
}

static int
smtp_client_connection_init_ssl_ctx(struct smtp_client_connection *conn,
				    const char **error_r)
{
	struct smtp_client *client = conn->client;
	const char *error;

	if (conn->ssl_ctx != NULL)
		return 0;

	if (conn->set.ssl == client->set.ssl) {
		if (smtp_client_init_ssl_ctx(client, error_r) < 0)
			return -1;
		conn->ssl_ctx = client->ssl_ctx;
		ssl_iostream_context_ref(conn->ssl_ctx);
		return 0;
	}

	if (conn->set.ssl == NULL) {
		*error_r =
			"Requested SSL connection, but no SSL settings given";
		return -1;
	}
	if (ssl_iostream_client_context_cache_get(conn->set.ssl, &conn->ssl_ctx,
						  &error) < 0) {
		*error_r = t_strdup_printf(
			"Couldn't initialize SSL context: %s", error);
		return -1;
	}
	return 0;
}

static int
smtp_client_connection_ssl_init(struct smtp_client_connection *conn,
				const char **error_r)
{
	const char *error;

	if (smtp_client_connection_init_ssl_ctx(conn, &error) < 0) {
		*error_r = t_strdup_printf(
			"Failed to initialize SSL: %s", error);
		return -1;
	}

	e_debug(conn->event, "Starting SSL handshake");

	if (conn->raw_input != conn->conn.input) {
		/* recreate rawlog after STARTTLS */
		i_stream_ref(conn->raw_input);
		o_stream_ref(conn->raw_output);
		i_stream_destroy(&conn->conn.input);
		o_stream_destroy(&conn->conn.output);
		conn->conn.input = conn->raw_input;
		conn->conn.output = conn->raw_output;
	}

	connection_input_halt(&conn->conn);
	if (io_stream_create_ssl_client(
		conn->ssl_ctx, conn->host, conn->set.ssl,
		&conn->conn.input, &conn->conn.output,
		&conn->ssl_iostream, &error) < 0) {
		*error_r = t_strdup_printf(
			"Couldn't initialize SSL client for %s: %s",
			conn->conn.name, error);
		return -1;
	}
	connection_input_resume(&conn->conn);
	smtp_client_connection_streams_changed(conn);

	ssl_iostream_set_handshake_callback(
		conn->ssl_iostream, smtp_client_connection_ssl_handshaked,
		conn);
	if (ssl_iostream_handshake(conn->ssl_iostream) < 0) {
		*error_r = t_strdup_printf(
			"SSL handshake to %s failed: %s", conn->conn.name,
			ssl_iostream_get_last_error(conn->ssl_iostream));
		return -1;
	}

	if (ssl_iostream_is_handshaked(conn->ssl_iostream) &&
	    !conn->connect_succeeded) {
		smtp_client_connection_established(conn);
	} else {
		/* wait for handshake to complete; connection input handler
		   does the rest by reading from the input stream */
		o_stream_set_flush_callback(
			conn->conn.output, smtp_client_connection_output, conn);
	}
	return 0;
}

static void
smtp_client_connection_connected(struct connection *_conn, bool success)
{
	struct smtp_client_connection *conn =
		(struct smtp_client_connection *)_conn;
	const struct smtp_client_settings *set = &conn->set;
	const char *error;

	if (!success) {
		e_error(conn->event, "connect(%s) failed: %m", _conn->name);
		conn->connect_failed = TRUE;
		return;
	}

	if (conn->set.debug) {
		struct ip_addr local_ip;
		in_port_t local_port;
		int ret;

		ret = net_getsockname(_conn->fd_in, &local_ip, &local_port);
		i_assert(ret == 0);
		e_debug(conn->event, "Connected to server (from %s:%u)",
			net_ip2addr(&local_ip), local_port);
	}

	(void)net_set_tcp_nodelay(_conn->fd_out, TRUE);
	if (set->socket_send_buffer_size > 0 &&
	    net_set_send_buffer_size(_conn->fd_out,
				     set->socket_send_buffer_size) < 0) {
		e_error(conn->event,
			"net_set_send_buffer_size(%zu) failed: %m",
			set->socket_send_buffer_size);
	}
	if (set->socket_recv_buffer_size > 0 &&
	    net_set_recv_buffer_size(_conn->fd_in,
				     set->socket_recv_buffer_size) < 0) {
		e_error(conn->event,
			"net_set_recv_buffer_size(%zu) failed: %m",
			set->socket_recv_buffer_size);
	}

	conn->raw_input = conn->conn.input;
	conn->raw_output = conn->conn.output;
	smtp_client_connection_streams_changed(conn);

	if (conn->ssl_mode == SMTP_CLIENT_SSL_MODE_IMMEDIATE) {
		if (smtp_client_connection_ssl_init(conn, &error) < 0) {
			e_error(conn->event, "connect(%s) failed: %s",
				_conn->name, error);
			smtp_client_connection_fail(
				conn, SMTP_CLIENT_COMMAND_ERROR_CONNECT_FAILED,
				"Failed to connect to remote server");
		}
	} else {
		smtp_client_connection_established(conn);
		smtp_client_connection_input(_conn);
	}
}

static void
smtp_client_connection_connect_timeout(struct smtp_client_connection *conn)
{
	switch (conn->state) {
	case SMTP_CLIENT_CONNECTION_STATE_CONNECTING:
		e_error(conn->event, "connect(%s) failed: "
			"Connection timed out after %u seconds",
			conn->conn.name,
			conn->set.connect_timeout_msecs/1000);
		smtp_client_connection_fail(
			conn, SMTP_CLIENT_COMMAND_ERROR_CONNECT_FAILED,
			"Connect timed out");
		break;
	case SMTP_CLIENT_CONNECTION_STATE_HANDSHAKING:
		e_error(conn->event,
			"SMTP handshake timed out after %u seconds",
			conn->set.connect_timeout_msecs/1000);
		smtp_client_connection_fail(
			conn, SMTP_CLIENT_COMMAND_ERROR_CONNECT_FAILED,
			"Handshake timed out");
		break;
	case SMTP_CLIENT_CONNECTION_STATE_AUTHENTICATING:
		e_error(conn->event,
			"Authentication timed out after %u seconds",
			conn->set.connect_timeout_msecs/1000);
		smtp_client_connection_fail(
			conn, SMTP_CLIENT_COMMAND_ERROR_AUTH_FAILED,
			"Authentication timed out");
		break;
	default:
		i_unreached();
	}
}

static void
smtp_client_connection_delayed_connect_error(struct smtp_client_connection *conn)
{
	e_debug(conn->event, "Delayed connect error");

	timeout_remove(&conn->to_connect);
	errno = conn->connect_errno;
	smtp_client_connection_connected(&conn->conn, FALSE);
	smtp_client_connection_fail(conn,
		SMTP_CLIENT_COMMAND_ERROR_CONNECT_FAILED,
		"Failed to connect to remote server");
}

static void
smtp_client_connection_do_connect(struct smtp_client_connection *conn)
{
	unsigned int msecs;

	if (conn->closed || conn->failing)
		return;

	/* Clear state data */
	i_zero(&conn->state_data);
	p_clear(conn->state_pool);

	if (connection_client_connect(&conn->conn) < 0) {
		conn->connect_errno = errno;
		e_debug(conn->event, "Connect failed: %m");
		conn->to_connect = timeout_add_short(0,
			smtp_client_connection_delayed_connect_error, conn);
		return;
	}

	/* don't use connection.h timeout because we want this timeout
	   to include also the SSL handshake */
	msecs = conn->set.connect_timeout_msecs;
	if (msecs == 0)
		msecs = conn->set.command_timeout_msecs;
	i_assert(conn->to_connect == NULL);
	if (msecs > 0) {
		conn->to_connect = timeout_add(
			msecs, smtp_client_connection_connect_timeout, conn);
	}
}

static bool
smtp_client_connection_last_ip(struct smtp_client_connection *conn)
{
	i_assert(conn->prev_connect_idx < conn->ips_count);
	return (conn->prev_connect_idx + 1) % conn->ips_count == 0;
}

static void
smtp_client_connection_connect_next_ip(struct smtp_client_connection *conn)
{
	const struct ip_addr *ip, *my_ip = &conn->set.my_ip;

	timeout_remove(&conn->to_connect);

	conn->prev_connect_idx = (conn->prev_connect_idx+1) % conn->ips_count;
	ip = &conn->ips[conn->prev_connect_idx];

	if (my_ip->family != 0) {
		e_debug(conn->event, "Connecting to %s:%u (from %s)",
			net_ip2addr(ip), conn->port, net_ip2addr(my_ip));
	} else {
		e_debug(conn->event, "Connecting to %s:%u",
			net_ip2addr(ip), conn->port);
	}

	connection_init_client_ip_from(conn->client->conn_list, &conn->conn,
				       (conn->host_is_ip ? NULL : conn->host),
				       ip, conn->port, my_ip);

	smtp_client_connection_do_connect(conn);
}

static void
smtp_client_connection_connect_unix(struct smtp_client_connection *conn)
{
	timeout_remove(&conn->to_connect);

	e_debug(conn->event, "Connecting to socket %s", conn->path);

	connection_init_client_unix(conn->client->conn_list, &conn->conn,
				    conn->path);

	smtp_client_connection_do_connect(conn);
}

static void
smtp_client_connection_delayed_host_lookup_failure(
	struct smtp_client_connection *conn)
{
	e_debug(conn->event, "Delayed host lookup failure");

	i_assert(conn->to_connect != NULL);
	timeout_remove(&conn->to_connect);
	smtp_client_connection_fail(
		conn, SMTP_CLIENT_COMMAND_ERROR_HOST_LOOKUP_FAILED,
		"Failed to lookup remote server");
}

static void
smtp_client_connection_dns_callback(const struct dns_lookup_result *result,
				    struct smtp_client_connection *conn)
{
	conn->dns_lookup = NULL;

	if (result->ret != 0) {
		e_error(conn->event, "dns_lookup(%s) failed: %s",
			conn->host, result->error);
		timeout_remove(&conn->to_connect);
		conn->to_connect = timeout_add_short(
			0, smtp_client_connection_delayed_host_lookup_failure,
			conn);
		return;
	}

	e_debug(conn->event, "DNS lookup successful; got %d IPs",
		result->ips_count);

	i_assert(result->ips_count > 0);
	conn->ips_count = result->ips_count;
	conn->ips = i_new(struct ip_addr, conn->ips_count);
	memcpy(conn->ips, result->ips, sizeof(*conn->ips) * conn->ips_count);
	conn->prev_connect_idx = conn->ips_count - 1;

	smtp_client_connection_connect_next_ip(conn);
}

static void
smtp_client_connection_lookup_ip(struct smtp_client_connection *conn)
{
	struct dns_lookup_settings dns_set;
	struct ip_addr ip, *ips;
	unsigned int ips_count;
	int ret;

	if (conn->ips_count != 0)
		return;

	e_debug(conn->event, "Looking up IP address");

	if (net_addr2ip(conn->host, &ip) == 0) {
		/* IP address */
		conn->ips_count = 1;
		conn->ips = i_new(struct ip_addr, conn->ips_count);
		conn->ips[0] = ip;
		conn->host_is_ip = TRUE;
	} else if (conn->set.dns_client != NULL) {
		e_debug(conn->event, "Performing asynchronous DNS lookup");
		(void)dns_client_lookup(
			conn->set.dns_client, conn->host,
			smtp_client_connection_dns_callback, conn,
			&conn->dns_lookup);
	} else if (conn->set.dns_client_socket_path != NULL) {
		i_zero(&dns_set);
		dns_set.dns_client_socket_path =
			conn->set.dns_client_socket_path;
		dns_set.timeout_msecs = conn->set.connect_timeout_msecs;
		dns_set.event_parent = conn->event;
		e_debug(conn->event, "Performing asynchronous DNS lookup");
		(void)dns_lookup(conn->host, &dns_set,
				 smtp_client_connection_dns_callback, conn,
				 &conn->dns_lookup);
	} else {
		/* no dns-conn, use blocking lookup */
		ret = net_gethostbyname(conn->host, &ips, &ips_count);
		if (ret != 0) {
			e_error(conn->event, "net_gethostbyname(%s) failed: %s",
				conn->host, net_gethosterror(ret));
			timeout_remove(&conn->to_connect);
			conn->to_connect = timeout_add_short(
				0,
				smtp_client_connection_delayed_host_lookup_failure,
				conn);
			return;
		}

		e_debug(conn->event, "DNS lookup successful; got %d IPs",
			ips_count);

		conn->ips_count = ips_count;
		conn->ips = i_new(struct ip_addr, ips_count);
		memcpy(conn->ips, ips, ips_count * sizeof(*ips));
	}
}

static void
smtp_client_connection_already_connected(struct smtp_client_connection *conn)
{
	i_assert(conn->state_data.login_reply != NULL);

	timeout_remove(&conn->to_connect);

	e_debug(conn->event, "Already connected");

	smtp_client_connection_login_callback(
		conn, conn->state_data.login_reply);
}

static void
smtp_client_connection_connect_more(struct smtp_client_connection *conn)
{
	if (!array_is_created(&conn->login_callbacks) ||
	    array_count(&conn->login_callbacks) == 0) {
		/* No login callbacks required */
		return;
	}
	if (conn->state < SMTP_CLIENT_CONNECTION_STATE_READY) {
		/* Login callbacks will be called once the connection succeeds
		   or fails. */
		return;
	}

	if (array_count(&conn->login_callbacks) > 1) {
		/* Another login callback is already pending */
		i_assert(conn->to_connect != NULL);
		return;
	}

	/* Schedule immediate login callback */
	i_assert(conn->to_connect == NULL);
	conn->to_connect = timeout_add(
		0, smtp_client_connection_already_connected, conn);
}

void smtp_client_connection_connect(
	struct smtp_client_connection *conn,
	smtp_client_command_callback_t login_callback, void *login_context)
{
	struct smtp_client_login_callback *login_cb;

	if (conn->closed)
		return;

	if (login_callback != NULL) {
		if (!array_is_created(&conn->login_callbacks))
			i_array_init(&conn->login_callbacks, 4);

		login_cb = array_append_space(&conn->login_callbacks);
		login_cb->callback = login_callback;
		login_cb->context = login_context;
	}

	if (conn->state != SMTP_CLIENT_CONNECTION_STATE_DISCONNECTED) {
		/* Already connecting or connected */
		smtp_client_connection_connect_more(conn);
		return;
	}
	if (conn->failing)
		return;

	e_debug(conn->event, "Disconnected");

	conn->xclient_replies_expected = 0;
	conn->authenticated = FALSE;
	conn->xclient_sent = FALSE;
	conn->connect_failed = FALSE;
	conn->connect_succeeded = FALSE;
	conn->handshake_failed = FALSE;
	conn->sent_quit = FALSE;
	conn->reset_needed = FALSE;

	smtp_client_connection_set_state(
		conn, SMTP_CLIENT_CONNECTION_STATE_CONNECTING);

	if (conn->path == NULL) {
		smtp_client_connection_lookup_ip(conn);
		if (conn->ips_count == 0)
			return;

		/* always work asynchronously */
		timeout_remove(&conn->to_connect);
		conn->to_connect = timeout_add(
			0, smtp_client_connection_connect_next_ip, conn);
	} else {
		/* always work asynchronously */
		timeout_remove(&conn->to_connect);
		conn->to_connect = timeout_add(
			0, smtp_client_connection_connect_unix, conn);
	}
}

static const struct connection_settings smtp_client_connection_set = {
	.input_max_size = SIZE_MAX,
	.output_max_size = SIZE_MAX,
	.client = TRUE,
	.delayed_unix_client_connected_callback = TRUE,
	.log_connection_id = TRUE,
};

static const struct connection_vfuncs smtp_client_connection_vfuncs = {
	.destroy = smtp_client_connection_destroy,
	.input = smtp_client_connection_input,
	.client_connected = smtp_client_connection_connected
};

struct connection_list *smtp_client_connection_list_init(void)
{
	return connection_list_init(&smtp_client_connection_set,
				    &smtp_client_connection_vfuncs);
}

void smtp_client_connection_disconnect(struct smtp_client_connection *conn)
{
	if (conn->state == SMTP_CLIENT_CONNECTION_STATE_DISCONNECTED)
		return;

	e_debug(conn->event, "Disconnected");

	smtp_client_connection_clear_password(conn);

	if (conn->conn.output != NULL && !conn->sent_quit &&
	    !conn->sending_command) {
		/* Close the connection gracefully if possible */
		o_stream_nsend_str(conn->conn.output, "QUIT\r\n");
		o_stream_uncork(conn->conn.output);
	}

	if (conn->dns_lookup != NULL)
		dns_lookup_abort(&conn->dns_lookup);
	io_remove(&conn->io_cmd_payload);
	timeout_remove(&conn->to_connect);
	timeout_remove(&conn->to_trans);
	timeout_remove(&conn->to_commands);
	timeout_remove(&conn->to_cmd_fail);

	ssl_iostream_destroy(&conn->ssl_iostream);
	if (conn->ssl_ctx != NULL)
		ssl_iostream_context_unref(&conn->ssl_ctx);
	if (conn->sasl_client != NULL)
		dsasl_client_free(&conn->sasl_client);

	o_stream_destroy(&conn->dot_output);

	connection_disconnect(&conn->conn);

	smtp_client_connection_set_state(
		conn, SMTP_CLIENT_CONNECTION_STATE_DISCONNECTED);

	if (!conn->failing) {
		smtp_client_connection_login_fail(
			conn, SMTP_CLIENT_COMMAND_ERROR_ABORTED,
			"Disconnected from server");
		smtp_client_connection_commands_fail(
			conn, SMTP_CLIENT_COMMAND_ERROR_ABORTED,
			"Disconnected from server");
	}
	smtp_client_command_unref(&conn->cmd_streaming);
}

static struct smtp_client_connection *
smtp_client_connection_do_create(struct smtp_client *client, const char *name,
				 enum smtp_protocol protocol,
				 const struct smtp_client_settings *set)
{
	struct smtp_client_connection *conn;
	struct event *conn_event;
	pool_t pool;

	pool = pool_alloconly_create("smtp client connection", 2048);
	conn = p_new(pool, struct smtp_client_connection, 1);
	conn->refcount = 1;
	conn->pool = pool;

	conn->client = client;
	conn->protocol = protocol;

	conn->set = client->set;
	if (set != NULL) {
		if (set->my_ip.family != 0)
			conn->set.my_ip = set->my_ip;
		if (set->my_hostname != NULL && *set->my_hostname != '\0')
			conn->set.my_hostname = p_strdup(pool, set->my_hostname);

		conn->set.forced_capabilities |= set->forced_capabilities;
		if (set->extra_capabilities != NULL) {
			conn->set.extra_capabilities =
				p_strarray_dup(pool, set->extra_capabilities);
		}

		if (set->rawlog_dir != NULL && *set->rawlog_dir != '\0')
			conn->set.rawlog_dir = p_strdup_empty(pool, set->rawlog_dir);

		if (set->ssl != NULL)
			conn->set.ssl = ssl_iostream_settings_dup(pool, set->ssl);

		if (set->master_user != NULL && *set->master_user != '\0')
			conn->set.master_user = p_strdup_empty(pool, set->master_user);
		if (set->username != NULL && *set->username != '\0')
			conn->set.username = p_strdup_empty(pool, set->username);
		if (set->password != NULL && *set->password != '\0') {
			conn->password = p_strdup(pool, set->password);
			conn->set.password = conn->password;
		}
		if (set->sasl_mech != NULL)
			conn->set.sasl_mech = set->sasl_mech;
		else if (set->sasl_mechanisms != NULL &&
			 *set->sasl_mechanisms != '\0') {
			conn->set.sasl_mechanisms =
				p_strdup(pool, set->sasl_mechanisms);
		}
		conn->set.remember_password = set->remember_password;

		if (set->command_timeout_msecs > 0)
			conn->set.command_timeout_msecs = set->command_timeout_msecs;
		if (set->connect_timeout_msecs > 0)
			conn->set.connect_timeout_msecs = set->connect_timeout_msecs;
		if (set->max_reply_size > 0)
			conn->set.max_reply_size = set->max_reply_size;
		if (set->max_data_chunk_size > 0)
			conn->set.max_data_chunk_size = set->max_data_chunk_size;
		if (set->max_data_chunk_pipeline > 0)
			conn->set.max_data_chunk_pipeline = set->max_data_chunk_pipeline;

		if (set->socket_send_buffer_size > 0)
			conn->set.socket_send_buffer_size = set->socket_send_buffer_size;
		if (set->socket_recv_buffer_size > 0)
			conn->set.socket_recv_buffer_size = set->socket_recv_buffer_size;
		conn->set.debug = conn->set.debug || set->debug;

		smtp_proxy_data_merge(conn->pool, &conn->set.proxy_data,
				      &set->proxy_data);
		conn->set.xclient_defer = set->xclient_defer;
		conn->set.peer_trusted = set->peer_trusted;

		conn->set.mail_send_broken_path = set->mail_send_broken_path;
	}


	if (set != NULL && set->extra_capabilities != NULL) {
		const char *const *extp;

		p_array_init(&conn->extra_capabilities, pool,
			     str_array_length(set->extra_capabilities) + 8);
		for (extp = set->extra_capabilities; *extp != NULL; extp++) {
			struct smtp_client_capability_extra cap = {
				.name = p_strdup(pool, *extp),
			};

			array_push_back(&conn->extra_capabilities, &cap);
		}
	}

	i_assert(conn->set.my_hostname != NULL &&
		*conn->set.my_hostname != '\0');

	conn->caps.standard = conn->set.forced_capabilities;
	conn->cap_pool = pool_alloconly_create(
		"smtp client connection capabilities", 128);
	conn->state_pool = pool_alloconly_create(
		"smtp client connection state", 256);

	if (set != NULL && set->event_parent != NULL)
		conn_event = event_create(set->event_parent);
	else
		conn_event = event_create(client->event);
	event_set_append_log_prefix(
		conn_event,
		t_strdup_printf("%s-client: ",
				smtp_protocol_name(conn->protocol)));
	event_add_str(conn_event, "protocol",
		      smtp_protocol_name(conn->protocol));
	event_set_forced_debug(conn_event, (set != NULL && set->debug));

	conn->conn.event_parent = conn_event;
	connection_init(conn->client->conn_list, &conn->conn, name);
	conn->event = conn->conn.event;
	event_unref(&conn_event);

	return conn;
}

struct smtp_client_connection *
smtp_client_connection_create(struct smtp_client *client,
			      enum smtp_protocol protocol,
			      const char *host, in_port_t port,
			      enum smtp_client_connection_ssl_mode ssl_mode,
			      const struct smtp_client_settings *set)
{
	struct smtp_client_connection *conn;
	const char *name = t_strdup_printf("%s:%u", host, port);

	conn = smtp_client_connection_do_create(client, name, protocol, set);
	conn->host = p_strdup(conn->pool, host);
	conn->port = port;
	conn->ssl_mode = ssl_mode;

	event_add_str(conn->event, "host", host);

	e_debug(conn->event, "Connection created");

	return conn;
}

struct smtp_client_connection *
smtp_client_connection_create_ip(struct smtp_client *client,
				 enum smtp_protocol protocol,
				 const struct ip_addr *ip, in_port_t port,
				 const char *hostname,
				 enum smtp_client_connection_ssl_mode ssl_mode,
				 const struct smtp_client_settings *set)
{
	struct smtp_client_connection *conn;
	bool host_is_ip = FALSE;

	if (hostname == NULL) {
		hostname = net_ip2addr(ip);
		host_is_ip = TRUE;
	}

	conn = smtp_client_connection_create(client, protocol, hostname, port,
					     ssl_mode, set);
	conn->ips_count = 1;
	conn->ips = i_new(struct ip_addr, conn->ips_count);
	conn->ips[0] = *ip;
	conn->host_is_ip = host_is_ip;
	return conn;
}

struct smtp_client_connection *
smtp_client_connection_create_unix(struct smtp_client *client,
				   enum smtp_protocol protocol,
				   const char *path,
				   const struct smtp_client_settings *set)
{
	struct smtp_client_connection *conn;
	const char *name = t_strconcat("unix:", path, NULL);

	conn = smtp_client_connection_do_create(client, name, protocol, set);
	conn->path = p_strdup(conn->pool, path);

	e_debug(conn->event, "Connection created");

	return conn;
}

void smtp_client_connection_ref(struct smtp_client_connection *conn)
{
	i_assert(conn->refcount >= 0);
	conn->refcount++;
}

void smtp_client_connection_unref(struct smtp_client_connection **_conn)
{
	struct smtp_client_connection *conn = *_conn;

	*_conn = NULL;

	i_assert(conn->refcount > 0);
	if (--conn->refcount > 0)
		return;
	if (conn->destroying)
		return;

	conn->destroying = TRUE;

	smtp_client_connection_clear_password(conn);
	smtp_client_connection_disconnect(conn);

	/* could have been created while already disconnected */
	timeout_remove(&conn->to_commands);
	timeout_remove(&conn->to_cmd_fail);

	e_debug(conn->event, "Destroy");

	if (conn->reply_parser != NULL)
		smtp_reply_parser_deinit(&conn->reply_parser);

	smtp_client_connection_login_fail(
		conn, SMTP_CLIENT_COMMAND_ERROR_ABORTED,
		"Connection destroy");
	smtp_client_connection_commands_fail(
		conn, SMTP_CLIENT_COMMAND_ERROR_ABORTED,
		"Connection destroy");

	connection_deinit(&conn->conn);

	i_free(conn->ips);
	array_free(&conn->login_callbacks);
	pool_unref(&conn->cap_pool);
	pool_unref(&conn->state_pool);
	pool_unref(&conn->pool);
}

void smtp_client_connection_close(struct smtp_client_connection **_conn)
{
	struct smtp_client_connection *conn = *_conn;

	*_conn = NULL;

	if (conn->closed)
		return;
	conn->closed = TRUE;

	smtp_client_connection_disconnect(conn);

	/* could have been created while already disconnected */
	timeout_remove(&conn->to_commands);
	timeout_remove(&conn->to_cmd_fail);

	smtp_client_connection_unref(&conn);
}

void smtp_client_connection_update_proxy_data(
	struct smtp_client_connection *conn,
	const struct smtp_proxy_data *proxy_data)
{
	if (conn->xclient_sent)
		return;

	smtp_proxy_data_merge(conn->pool, &conn->set.proxy_data, proxy_data);
}

void smtp_client_connection_switch_ioloop(struct smtp_client_connection *conn)
{
	struct smtp_client_transaction *trans;

	if (conn->io_cmd_payload != NULL)
		conn->io_cmd_payload = io_loop_move_io(&conn->io_cmd_payload);
	if (conn->to_connect != NULL)
		conn->to_connect = io_loop_move_timeout(&conn->to_connect);
	if (conn->to_trans != NULL)
		conn->to_trans = io_loop_move_timeout(&conn->to_trans);
	if (conn->to_commands != NULL)
		conn->to_commands = io_loop_move_timeout(&conn->to_commands);
	if (conn->to_cmd_fail != NULL)
		conn->to_cmd_fail = io_loop_move_timeout(&conn->to_cmd_fail);
	connection_switch_ioloop(&conn->conn);

	trans = conn->transactions_head;
	while (trans != NULL) {
		smtp_client_transaction_switch_ioloop(trans);
		trans = trans->next;
	}
}

static void
smtp_client_connection_rset_dummy_cb(
	const struct smtp_reply *reply ATTR_UNUSED,
	struct smtp_client_connection *conn ATTR_UNUSED)
{
	/* nothing */
}

static void
smtp_client_connection_reset(struct smtp_client_connection *conn)
{
	e_debug(conn->event, "Submitting RSET command");

	conn->reset_needed = FALSE;

	(void)smtp_client_command_rset_submit(
		conn, SMTP_CLIENT_COMMAND_FLAG_PRIORITY,
		smtp_client_connection_rset_dummy_cb, conn);
}

static void
smtp_client_connection_do_start_transaction(struct smtp_client_connection *conn)
{
	struct smtp_reply reply;

	timeout_remove(&conn->to_trans);

	if (conn->state != SMTP_CLIENT_CONNECTION_STATE_TRANSACTION)
		return;
	if (conn->transactions_head == NULL) {
		smtp_client_connection_set_state(
			conn, SMTP_CLIENT_CONNECTION_STATE_READY);
		return;
	}

	if (conn->reset_needed)
		smtp_client_connection_reset(conn);

	e_debug(conn->event, "Start next transaction");

	smtp_reply_init(&reply, 200, "Connection ready");
	smtp_client_transaction_connection_result(
		conn->transactions_head, &reply);
}

static void
smtp_client_connection_start_transaction(struct smtp_client_connection *conn)
{
	if (conn->state != SMTP_CLIENT_CONNECTION_STATE_READY)
		return;
	if (conn->transactions_head == NULL)
		return;
	if (conn->to_trans != NULL)
		return;

	smtp_client_connection_set_state(
		conn, SMTP_CLIENT_CONNECTION_STATE_TRANSACTION);
	conn->to_trans = timeout_add_short(
		0, smtp_client_connection_do_start_transaction, conn);
}

void smtp_client_connection_add_transaction(
	struct smtp_client_connection *conn,
	struct smtp_client_transaction *trans)
{
	e_debug(conn->event, "Add transaction");

	DLLIST2_APPEND(&conn->transactions_head, &conn->transactions_tail,
		       trans);

	smtp_client_connection_connect(conn, NULL, NULL);
	smtp_client_connection_start_transaction(conn);
}

void smtp_client_connection_abort_transaction(
	struct smtp_client_connection *conn,
	struct smtp_client_transaction *trans)
{
	bool was_first = (trans == conn->transactions_head);

	e_debug(conn->event, "Abort transaction");

	DLLIST2_REMOVE(&conn->transactions_head, &conn->transactions_tail,
		       trans);

	if (!was_first)
		return;
	i_assert(conn->state != SMTP_CLIENT_CONNECTION_STATE_READY);
	if (conn->state != SMTP_CLIENT_CONNECTION_STATE_TRANSACTION)
		return;

	/* transaction messed up; protocol state needs to be reset for
	   next transaction */
	conn->reset_needed = TRUE;

	smtp_client_connection_set_state(
		conn, SMTP_CLIENT_CONNECTION_STATE_READY);
	smtp_client_connection_start_transaction(conn);
}

void smtp_client_connection_next_transaction(
	struct smtp_client_connection *conn,
	struct smtp_client_transaction *trans)
{
	e_debug(conn->event, "Initiate next transaction");

	i_assert(trans == conn->transactions_head);

	DLLIST2_REMOVE(&conn->transactions_head, &conn->transactions_tail,
		       trans);

	i_assert(conn->state != SMTP_CLIENT_CONNECTION_STATE_READY);
	if (conn->state != SMTP_CLIENT_CONNECTION_STATE_TRANSACTION)
		return;

	smtp_client_connection_set_state(
		conn, SMTP_CLIENT_CONNECTION_STATE_READY);
	smtp_client_connection_start_transaction(conn);
}
