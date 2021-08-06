/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "smtp-address.h"
#include "smtp-reply.h"

#include "smtp-server-private.h"

/*
 * Reply
 */

static void smtp_server_reply_destroy(struct smtp_server_reply *reply)
{
	if (reply->command == NULL)
		return;

	if (reply->event != NULL) {
		e_debug(reply->event, "Destroy");
		event_unref(&reply->event);
	}

	if (reply->content == NULL)
		return;
	str_free(&reply->content->text);
}

static void smtp_server_reply_clear(struct smtp_server_reply *reply)
{
	smtp_server_reply_destroy(reply);
	if (reply->submitted) {
		i_assert(reply->command->replies_submitted > 0);
		reply->command->replies_submitted--;
	}
	reply->submitted = FALSE;
	reply->forwarded = FALSE;
}

static void smtp_server_reply_update_event(struct smtp_server_reply *reply)
{
	struct smtp_server_command *command = reply->command;

	event_add_int(reply->event, "index", reply->index);
	event_add_int(reply->event, "status", reply->content->status);

	if (command->replies_expected > 1) {
		event_set_append_log_prefix(reply->event,
			t_strdup_printf("%u reply [%u/%u]: ",
					reply->content->status,
					reply->index+1,
					command->replies_expected));
	} else {
		event_set_append_log_prefix(reply->event,
			t_strdup_printf("%u reply: ",
					reply->content->status));
	}
}

static struct smtp_server_reply *
smtp_server_reply_alloc(struct smtp_server_command *cmd, unsigned int index)
{
	struct smtp_server_reply *reply;
	pool_t pool = cmd->context.pool;

	if (array_is_created(&cmd->replies)) {
		reply = array_idx_modifiable(&cmd->replies, index);
		/* get rid of any existing reply */
		i_assert(!reply->sent);
		smtp_server_reply_clear(reply);
	} else {
		p_array_init(&cmd->replies, pool, cmd->replies_expected);
		array_idx_clear(&cmd->replies, cmd->replies_expected - 1);
		reply = array_idx_modifiable(&cmd->replies, index);
	}
	reply->event = event_create(cmd->context.event);

	return reply;
}

static void
smtp_server_reply_update_prefix(struct smtp_server_reply *reply,
				unsigned int status, const char *enh_code)
{
	pool_t pool = reply->command->context.pool;
	string_t *textbuf, *new_text;
	const char *new_prefix, *text, *p;
	size_t text_len, prefix_len, line_len;

	if (enh_code == NULL || *enh_code == '\0') {
		new_prefix = p_strdup_printf(pool, "%03u-", status);
	} else {
		new_prefix = p_strdup_printf(pool, "%03u-%s ",
					     status, enh_code);
	}

	i_assert(reply->content != NULL);
	textbuf = reply->content->text;

	if (textbuf == NULL || str_len(textbuf) == 0) {
		reply->content->status_prefix = new_prefix;
		return;
	}
	new_text = str_new(default_pool, 256);

	prefix_len = strlen(reply->content->status_prefix);
	text = str_c(textbuf);
	text_len = str_len(textbuf);

	i_assert(text_len > prefix_len);
	text_len -= prefix_len;
	text += prefix_len;

	for (;;) {
		reply->content->last_line = str_len(new_text);

		p = strchr(text, '\n');
		i_assert(p != NULL && p > text && *(p-1) == '\r');
		p++;

		str_append(new_text, new_prefix);
		str_append_data(new_text, text, p - text);

		line_len = (size_t)(p - text);
		i_assert(text_len >= line_len);
		text_len -= line_len;
		text = p;

		if (text_len <= prefix_len)
			break;

		text_len -= prefix_len;
		text += prefix_len;
	}

	str_free(&textbuf);
	reply->content->text = new_text;
	reply->content->status_prefix = new_prefix;
}

void smtp_server_reply_set_status(struct smtp_server_reply *reply,
				  unsigned int status, const char *enh_code)
{
	pool_t pool = reply->command->context.pool;

	/* RFC 5321, Section 4.2:

	   In the absence of extensions negotiated with the client, SMTP servers
	   MUST NOT send reply codes whose first digits are other than 2, 3, 4,
	   or 5.  Clients that receive such out-of-range codes SHOULD normally
	   treat them as fatal errors and terminate the mail transaction.
	 */
	i_assert(status >= 200 && status < 560);

	/* RFC 2034, Section 4:

	   All status codes returned by the server must agree with the primary
	   response code, that is, a 2xx response must incorporate a 2.X.X code,
	   a 4xx response must incorporate a 4.X.X code, and a 5xx response must
	   incorporate a 5.X.X code.
	 */
	i_assert(enh_code == NULL || *enh_code == '\0' ||
		((unsigned int)(enh_code[0] - '0') == (status / 100)
			&& enh_code[1] == '.'));

	if (reply->content->status == status &&
	    null_strcmp(reply->content->enhanced_code, enh_code) == 0)
		return;

	smtp_server_reply_update_prefix(reply, status, enh_code);
	reply->content->status = status;
	reply->content->enhanced_code = p_strdup(pool, enh_code);
}

unsigned int smtp_server_reply_get_status(struct smtp_server_reply *reply,
					  const char **enh_code_r)
{
	if (enh_code_r != NULL)
		*enh_code_r = reply->content->enhanced_code;
	return reply->content->status;
}

struct smtp_server_reply *
smtp_server_reply_create_index(struct smtp_server_command *cmd,
			       unsigned int index, unsigned int status,
			       const char *enh_code)
{
	struct smtp_server_reply *reply;
	pool_t pool = cmd->context.pool;

	i_assert(cmd->replies_expected > 0);
	i_assert(index < cmd->replies_expected);

	reply = smtp_server_reply_alloc(cmd, index);
	reply->index = index;
	reply->command = cmd;

	if (reply->content == NULL)
		reply->content = p_new(pool, struct smtp_server_reply_content, 1);
	smtp_server_reply_set_status(reply, status, enh_code);
	reply->content->text = str_new(default_pool, 256);

	smtp_server_reply_update_event(reply);

	return reply;
}

struct smtp_server_reply *
smtp_server_reply_create(struct smtp_server_command *cmd,
			 unsigned int status, const char *enh_code)
{
	return smtp_server_reply_create_index(cmd, 0, status, enh_code);
}

struct smtp_server_reply *
smtp_server_reply_create_forward(struct smtp_server_command *cmd,
	unsigned int index, const struct smtp_reply *from)
{
	struct smtp_server_reply *reply;
	string_t *textbuf;
	char *text;
	size_t last_line, i;

	reply = smtp_server_reply_create_index(cmd, index,
		from->status, smtp_reply_get_enh_code(from));
	smtp_reply_write(reply->content->text, from);

	i_assert(reply->content != NULL);
	textbuf = reply->content->text;
	text = str_c_modifiable(textbuf);

	/* Find the last line */
	reply->content->last_line = last_line = 0;
	for (i = 0; i < str_len(textbuf); i++) {
		if (text[i] == '\n') {
			reply->content->last_line = last_line;
			last_line = i + 1;
		}
	}

	/* Make this reply suitable for further amendment with
	   smtp_server_reply_add_text() */
	if ((reply->content->last_line + 3) < str_len(textbuf)) {
		i_assert(text[reply->content->last_line + 3] == ' ');
		text[reply->content->last_line + 3] = '-';
	} else {
		str_append_c(textbuf, '-');
	}

	reply->forwarded = TRUE;

	return reply;
}

void smtp_server_reply_free(struct smtp_server_command *cmd)
{
	unsigned int i;

	if (!array_is_created(&cmd->replies))
		return;

	for (i = 0; i < cmd->replies_expected; i++) {
		struct smtp_server_reply *reply =
			array_idx_modifiable(&cmd->replies, i);
		smtp_server_reply_destroy(reply);
	}
}

void smtp_server_reply_add_text(struct smtp_server_reply *reply,
				const char *text)
{
	string_t *textbuf = reply->content->text;

	i_assert(!reply->submitted);

	if (*text == '\0')
		return;

	do {
		const char *p;

		reply->content->last_line = str_len(textbuf);

		p = strchr(text, '\n');
		str_append(textbuf, reply->content->status_prefix);
		if (p == NULL) {
			str_append(textbuf, text);
			text = NULL;
		} else {
			if (p > text && *(p-1) == '\r')
				str_append_data(textbuf, text, p - text - 1);
			else
				str_append_data(textbuf, text, p - text);
			text = p + 1;
		}
		str_append(textbuf, "\r\n");
	} while (text != NULL && *text != '\0');
}

static size_t
smtp_server_reply_get_path_len(struct smtp_server_reply *reply)
{
	size_t prefix_len = strlen(reply->content->status_prefix);
	size_t text_len = str_len(reply->content->text), line_len, path_len;
	const char *text = str_c(reply->content->text);
	const char *text_end = text + text_len, *line_end;

	i_assert(prefix_len <= text_len);

	line_end = strchr(text, '\r');
	if (line_end == NULL) {
		line_end = text_end;
		line_len = text_len;
	} else {
		i_assert(line_end + 1 < text_end);
		i_assert(*(line_end + 1) == '\n');
		line_len = line_end - text;
	}

	if (prefix_len == line_len || text[prefix_len] != '<') {
		path_len = 0;
	} else {
		const char *path_begin = &text[prefix_len], *path_end;

		path_end = strchr(path_begin, '>');
		if (path_end == NULL || path_end > line_end)
			path_len = 0;
		else {
			i_assert(path_end < line_end);
			path_end++;
			path_len = path_end - path_begin;
			if (path_end < line_end && *path_end != ' ')
				path_len = 0;
		}
	}

	i_assert(prefix_len + path_len <= text_len);
	return path_len;
}

void smtp_server_reply_prepend_text(struct smtp_server_reply *reply,
				    const char *text_prefix)
{
	const char *text = str_c(reply->content->text);
	size_t tlen = str_len(reply->content->text), offset;

	i_assert(!reply->sent);
	i_assert(reply->content != NULL);
	i_assert(reply->content->text != NULL);

	offset = strlen(reply->content->status_prefix) +
		smtp_server_reply_get_path_len(reply);
	i_assert(offset < tlen);
	if (text[offset] == ' ')
		offset++;

	str_insert(reply->content->text, offset, text_prefix);

	if (reply->content->last_line > 0)
		reply->content->last_line += strlen(text_prefix);
}

void smtp_server_reply_replace_path(struct smtp_server_reply *reply,
				    struct smtp_address *path, bool add)
{
	size_t prefix_len, path_len;
	const char *path_text;

	i_assert(!reply->sent);
	i_assert(reply->content != NULL);
	i_assert(reply->content->text != NULL);

	prefix_len = strlen(reply->content->status_prefix);
	path_len = smtp_server_reply_get_path_len(reply);

	if (path_len > 0) {
		path_text = smtp_address_encode_path(path);
		str_replace(reply->content->text, prefix_len, path_len,
			    path_text);
	} else if (add) {
		path_text = t_strdup_printf(
			"<%s> ", smtp_address_encode(path));
		str_insert(reply->content->text, prefix_len, path_text);
	}
}

void smtp_server_reply_submit(struct smtp_server_reply *reply)
{
	i_assert(!reply->submitted);
	i_assert(reply->content != NULL);
	i_assert(str_len(reply->content->text) >= 5);
	e_debug(reply->event, "Submitted");

	reply->command->replies_submitted++;
	reply->submitted = TRUE;
	smtp_server_command_submit_reply(reply->command);
}

void smtp_server_reply_submit_duplicate(struct smtp_server_cmd_ctx *_cmd,
					unsigned int index,
					unsigned int from_index)
{
	struct smtp_server_command *cmd = _cmd->cmd;
	struct smtp_server_reply *reply, *from_reply;

	i_assert(cmd->replies_expected > 0);
	i_assert(index < cmd->replies_expected);
	i_assert(from_index < cmd->replies_expected);
	i_assert(array_is_created(&cmd->replies));

	from_reply = array_idx_modifiable(&cmd->replies, from_index);
	i_assert(from_reply->content != NULL);
	i_assert(from_reply->submitted);

	reply = smtp_server_reply_alloc(cmd, index);
	reply->index = index;
	reply->command = cmd;
	reply->content = from_reply->content;
	smtp_server_reply_update_event(reply);

	smtp_server_reply_submit(reply);
}

void smtp_server_reply_indexv(struct smtp_server_cmd_ctx *_cmd,
	unsigned int index, unsigned int status, const char *enh_code,
	const char *fmt, va_list args)
{
	struct smtp_server_command *cmd = _cmd->cmd;
	struct smtp_server_reply *reply;

	reply = smtp_server_reply_create_index(cmd, index, status, enh_code);
	smtp_server_reply_add_text(reply, t_strdup_vprintf(fmt, args));
	smtp_server_reply_submit(reply);
}

void smtp_server_reply(struct smtp_server_cmd_ctx *_cmd,
	unsigned int status, const char *enh_code, const char *fmt, ...)
{
	struct smtp_server_command *cmd = _cmd->cmd;
	va_list args;

	i_assert(cmd->replies_expected <= 1);

	va_start(args, fmt);
	smtp_server_reply_indexv(_cmd, 0, status, enh_code, fmt, args);
	va_end(args);
}

void smtp_server_reply_index(struct smtp_server_cmd_ctx *_cmd,
	unsigned int index, unsigned int status, const char *enh_code,
	const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	smtp_server_reply_indexv(_cmd, index, status, enh_code, fmt, args);
	va_end(args);
}

void smtp_server_reply_index_forward(struct smtp_server_cmd_ctx *cmd,
	unsigned int index, const struct smtp_reply *from)
{
	smtp_server_reply_submit(
		smtp_server_reply_create_forward(cmd->cmd, index, from));
}

void smtp_server_reply_forward(struct smtp_server_cmd_ctx *_cmd,
			       const struct smtp_reply *from)
{
	struct smtp_server_command *cmd = _cmd->cmd;

	i_assert(cmd->replies_expected <= 1);

	smtp_server_reply_submit(
		smtp_server_reply_create_forward(cmd, 0, from));
}

static void ATTR_FORMAT(4, 0)
smtp_server_reply_allv(struct smtp_server_cmd_ctx *_cmd,
		       unsigned int status, const char *enh_code,
		       const char *fmt, va_list args)
{
	struct smtp_server_command *cmd = _cmd->cmd;
	struct smtp_server_reply *reply;
	const char *text;
	unsigned int first, i = 0;

	/* find the first unsent reply */
	if (array_is_created(&cmd->replies)) {
		for (; i < cmd->replies_expected; i++) {
			struct smtp_server_reply *reply =
				array_idx_modifiable(&cmd->replies, i);
			if (!reply->sent)
				break;
		}
		i_assert (i < cmd->replies_expected);
	}
	first = i++;

	/* compose the reply text */
	text = t_strdup_vprintf(fmt, args);

	/* submit the first remaining reply */
	reply = smtp_server_reply_create_index(cmd, first, status, enh_code);
	smtp_server_reply_add_text(reply, text);
	smtp_server_reply_submit(reply);

	/* duplicate the rest from it */
	for (; i < cmd->replies_expected; i++)
		smtp_server_reply_submit_duplicate(_cmd, i, first);
}

void smtp_server_reply_all(struct smtp_server_cmd_ctx *_cmd,
			   unsigned int status, const char *enh_code,
			   const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	smtp_server_reply_allv(_cmd, status, enh_code, fmt, args);
	va_end(args);
}

void smtp_server_reply_early(struct smtp_server_cmd_ctx *_cmd,
			     unsigned int status, const char *enh_code,
			     const char *fmt, ...)
{
	va_list args;

	_cmd->cmd->reply_early = TRUE;

	va_start(args, fmt);
	smtp_server_reply_allv(_cmd, status, enh_code, fmt, args);
	va_end(args);
}

void smtp_server_reply_quit(struct smtp_server_cmd_ctx *_cmd)
{
	struct smtp_server_command *cmd = _cmd->cmd;
	struct smtp_server_reply *reply;

	reply = smtp_server_reply_create(cmd, 221, "2.0.0");
	smtp_server_reply_add_text(reply, "Bye");
	smtp_server_reply_submit(reply);
}

static void
smtp_server_reply_write_one_line(const struct smtp_server_reply *reply,
				 string_t *str, bool skip_status)
{
	string_t *textbuf;
	const char *text, *p;
	size_t text_len, prefix_len, line_len;

	i_assert(reply->content != NULL);
	textbuf = reply->content->text;
	i_assert(str_len(textbuf) > 0);

	prefix_len = strlen(reply->content->status_prefix);
	text = str_c(textbuf);
	text_len = str_len(textbuf);

	if (skip_status) {
		i_assert(text_len > prefix_len);
		text_len -= prefix_len;
		text += prefix_len;
	}

	for (;;) {
		p = strchr(text, '\n');
		i_assert(p != NULL && p > text && *(p-1) == '\r');
		str_append_data(str, text, p - text - 1);
		line_len = (size_t)(p - text) + 1;
		i_assert(text_len >= line_len);
		text_len -= line_len;
		text = p + 1;

		if (text_len <= prefix_len)
			break;

		text_len -= prefix_len;
		text += prefix_len;
		str_append_c(str, ' ');
	}
}

const char *
smtp_server_reply_get_one_line(const struct smtp_server_reply *reply)
{
	string_t *str = t_str_new(256);

	smtp_server_reply_write_one_line(reply, str, FALSE);
	return str_c(str);
}

const char *
smtp_server_reply_get_message(const struct smtp_server_reply *reply)
{
	string_t *str = t_str_new(256);

	smtp_server_reply_write_one_line(reply, str, TRUE);
	return str_c(str);
}

static int smtp_server_reply_send_real(struct smtp_server_reply *reply)
{
	struct smtp_server_command *cmd = reply->command;
	struct smtp_server_connection *conn = cmd->context.conn;
	struct ostream *output = conn->conn.output;
	string_t *textbuf;
	char *text;
	int ret = 0;

	i_assert(reply->content != NULL);
	textbuf = reply->content->text;
	i_assert(str_len(textbuf) > 0);

	/* substitute '-' with ' ' in last line */
	text = str_c_modifiable(textbuf);
	text = text + reply->content->last_line + 3;
	if (text[0] != ' ') {
		i_assert(text[0] == '-');
		text[0] = ' ';
	}

	if (o_stream_send(output, str_data(textbuf), str_len(textbuf)) < 0) {
		e_debug(reply->event, "Send failed: %s",
			o_stream_get_disconnect_reason(output));
		smtp_server_connection_handle_output_error(conn);
		return -1;
	}

	e_debug(reply->event, "Sent: %s",
		smtp_server_reply_get_one_line(reply));
	return ret;
}

int smtp_server_reply_send(struct smtp_server_reply *reply)
{
	int ret;

	if (reply->sent)
		return 0;

	T_BEGIN {
		ret = smtp_server_reply_send_real(reply);
	} T_END;

	reply->sent = TRUE;
	return ret;
}

bool smtp_server_reply_is_success(const struct smtp_server_reply *reply)
{
	i_assert(reply->content != NULL);
	return (reply->content->status / 100 == 2);
}

void smtp_server_reply_add_to_event(const struct smtp_server_reply *reply,
				    struct event_passthrough *e)
{
	i_assert(reply->content != NULL);
	e->add_int("status_code", reply->content->status);
	if (reply->content->enhanced_code != NULL &&
	    reply->content->enhanced_code[0] != '\0')
		e->add_str("enhanced_code", reply->content->enhanced_code);
	if (!smtp_server_reply_is_success(reply))
		e->add_str("error", smtp_server_reply_get_message(reply));
}

/*
 * EHLO reply
 */

struct smtp_server_reply *
smtp_server_reply_create_ehlo(struct smtp_server_command *cmd)
{
	struct smtp_server_connection *conn = cmd->context.conn;
	struct smtp_server_reply *reply;
	string_t *textbuf;

	reply = smtp_server_reply_create(cmd, 250, "");
	textbuf = reply->content->text;
	str_append(textbuf, reply->content->status_prefix);
	str_append(textbuf, conn->set.hostname);
	str_append(textbuf, "\r\n");

	return reply;
}

void smtp_server_reply_ehlo_add(struct smtp_server_reply *reply,
				const char *keyword)
{
	string_t *textbuf;

	i_assert(!reply->submitted);
	i_assert(reply->content != NULL);
	textbuf = reply->content->text;

	reply->content->last_line = str_len(textbuf);
	str_append(textbuf, reply->content->status_prefix);
	str_append(textbuf, keyword);
	str_append(textbuf, "\r\n");
}

void smtp_server_reply_ehlo_add_param(struct smtp_server_reply *reply,
	const char *keyword, const char *param_fmt, ...)
{
	va_list args;
	string_t *textbuf;

	i_assert(!reply->submitted);
	i_assert(reply->content != NULL);
	textbuf = reply->content->text;

	reply->content->last_line = str_len(textbuf);
	str_append(textbuf, reply->content->status_prefix);
	str_append(textbuf, keyword);
	if (*param_fmt != '\0') {
		va_start(args, param_fmt);
		str_append_c(textbuf, ' ');
		str_vprintfa(textbuf, param_fmt, args);
		va_end(args);
	}
	str_append(textbuf, "\r\n");
}

void smtp_server_reply_ehlo_add_params(struct smtp_server_reply *reply,
				       const char *keyword,
				       const char *const *params)
{
	string_t *textbuf;

	i_assert(!reply->submitted);
	i_assert(reply->content != NULL);
	textbuf = reply->content->text;

	reply->content->last_line = str_len(textbuf);
	str_append(textbuf, reply->content->status_prefix);
	str_append(textbuf, keyword);
	if (params != NULL) {
		while (*params != NULL) {
			str_append_c(textbuf, ' ');
			str_append(textbuf, *params);
			params++;
		}
	}
	str_append(textbuf, "\r\n");
}

void smtp_server_reply_ehlo_add_8bitmime(struct smtp_server_reply *reply)
{
	struct smtp_server_cmd_ctx *cmd = &reply->command->context;
	struct smtp_server_connection *conn = cmd->conn;
	enum smtp_capability caps = conn->set.capabilities;

	if ((caps & SMTP_CAPABILITY_8BITMIME) == 0)
		return;
	smtp_server_reply_ehlo_add(reply, "8BITMIME");
}

void smtp_server_reply_ehlo_add_binarymime(struct smtp_server_reply *reply)
{
	struct smtp_server_cmd_ctx *cmd = &reply->command->context;
	struct smtp_server_connection *conn = cmd->conn;
	enum smtp_capability caps = conn->set.capabilities;

	if ((caps & SMTP_CAPABILITY_BINARYMIME) == 0 ||
	    (caps & SMTP_CAPABILITY_CHUNKING) == 0)
		return;
	smtp_server_reply_ehlo_add(reply, "BINARYMIME");
}

void smtp_server_reply_ehlo_add_chunking(struct smtp_server_reply *reply)
{
	struct smtp_server_cmd_ctx *cmd = &reply->command->context;
	struct smtp_server_connection *conn = cmd->conn;
	enum smtp_capability caps = conn->set.capabilities;

	if ((caps & SMTP_CAPABILITY_CHUNKING) == 0)
		return;
	smtp_server_reply_ehlo_add(reply, "CHUNKING");
}

void smtp_server_reply_ehlo_add_dsn(struct smtp_server_reply *reply)
{
	struct smtp_server_cmd_ctx *cmd = &reply->command->context;
	struct smtp_server_connection *conn = cmd->conn;
	enum smtp_capability caps = conn->set.capabilities;

	if ((caps & SMTP_CAPABILITY_DSN) == 0)
		return;
	smtp_server_reply_ehlo_add(reply, "DSN");
}

void smtp_server_reply_ehlo_add_enhancedstatuscodes(
	struct smtp_server_reply *reply)
{
	struct smtp_server_cmd_ctx *cmd = &reply->command->context;
	struct smtp_server_connection *conn = cmd->conn;
	enum smtp_capability caps = conn->set.capabilities;

	if ((caps & SMTP_CAPABILITY_ENHANCEDSTATUSCODES) == 0)
		return;
	smtp_server_reply_ehlo_add(reply, "ENHANCEDSTATUSCODES");
}

void smtp_server_reply_ehlo_add_pipelining(struct smtp_server_reply *reply)
{
	smtp_server_reply_ehlo_add(reply, "PIPELINING");
}

void smtp_server_reply_ehlo_add_size(struct smtp_server_reply *reply)
{
	struct smtp_server_cmd_ctx *cmd = &reply->command->context;
	struct smtp_server_connection *conn = cmd->conn;
	enum smtp_capability caps = conn->set.capabilities;
	uoff_t cap_size = conn->set.max_message_size;

	if ((caps & SMTP_CAPABILITY_SIZE) == 0)
		return;

	if (cap_size > 0 && cap_size != UOFF_T_MAX) {
		smtp_server_reply_ehlo_add_param(reply,
			"SIZE", "%"PRIuUOFF_T, cap_size);
	} else {
		smtp_server_reply_ehlo_add(reply, "SIZE");
	}
}

void smtp_server_reply_ehlo_add_starttls(struct smtp_server_reply *reply)
{
	struct smtp_server_cmd_ctx *cmd = &reply->command->context;
	struct smtp_server_connection *conn = cmd->conn;
	enum smtp_capability caps = conn->set.capabilities;

	if ((caps & SMTP_CAPABILITY_STARTTLS) == 0)
		return;
	smtp_server_reply_ehlo_add(reply, "STARTTLS");
}

void smtp_server_reply_ehlo_add_vrfy(struct smtp_server_reply *reply)
{
	struct smtp_server_cmd_ctx *cmd = &reply->command->context;
	struct smtp_server_connection *conn = cmd->conn;
	enum smtp_capability caps = conn->set.capabilities;

	if ((caps & SMTP_CAPABILITY_VRFY) == 0)
		return;
	smtp_server_reply_ehlo_add(reply, "VRFY");
}

void smtp_server_reply_ehlo_add_xclient(struct smtp_server_reply *reply)
{
	static const char *base_fields =
		"ADDR PORT PROTO HELO LOGIN TTL TIMEOUT";
	struct smtp_server_cmd_ctx *cmd = &reply->command->context;
	struct smtp_server_connection *conn = cmd->conn;

	if (!smtp_server_connection_is_trusted(conn))
		return;
	if (conn->set.xclient_extensions == NULL ||
	    *conn->set.xclient_extensions == NULL) {
		smtp_server_reply_ehlo_add_param(reply, "XCLIENT", "%s",
			base_fields);
		return;
	}

	smtp_server_reply_ehlo_add_param(reply, "XCLIENT", "%s",
		t_strconcat(base_fields, " ",
			t_strarray_join(conn->set.xclient_extensions, " "),
			NULL));
}
