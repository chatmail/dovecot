#ifndef CLIENT_H
#define CLIENT_H

#include "net.h"
#include "client-common.h"

/* maximum length for managesieve command line. */
#define MAX_MANAGESIEVE_LINE 8192

enum managesieve_proxy_state {
	MSIEVE_PROXY_STATE_NONE,
	MSIEVE_PROXY_STATE_TLS_START,
	MSIEVE_PROXY_STATE_TLS_READY,
	MSIEVE_PROXY_STATE_XCLIENT,
	MSIEVE_PROXY_STATE_AUTH,

	MSIEVE_PROXY_STATE_COUNT
};
struct managesieve_command;

struct managesieve_client {
	struct client common;

	const struct managesieve_login_settings *set;
	struct managesieve_parser *parser;

	enum managesieve_proxy_state proxy_state;

	const char *cmd_name;
	struct managesieve_command *cmd;

	struct istream *auth_response_input;

	bool cmd_finished:1;
	bool cmd_parsed_args:1;
	bool skip_line:1;
	bool auth_mech_name_parsed:1;

	bool proxy_starttls:1;
	bool proxy_sasl:1;
	bool proxy_xclient:1;
};

bool client_skip_line(struct managesieve_client *client);

enum managesieve_cmd_reply {
	MANAGESIEVE_CMD_REPLY_OK,
	MANAGESIEVE_CMD_REPLY_NO,
	MANAGESIEVE_CMD_REPLY_BYE
};

void client_send_reply(struct client *client, enum managesieve_cmd_reply reply,
		       const char *text);

void client_send_reply_code(struct client *client,
			    enum managesieve_cmd_reply reply,
			    const char *resp_code, const char *text);

#define client_send_ok(client, text) \
	client_send_reply(client, MANAGESIEVE_CMD_REPLY_OK, text)
#define client_send_no(client, text) \
	client_send_reply(client, MANAGESIEVE_CMD_REPLY_NO, text)
#define client_send_bye(client, text) \
	client_send_reply(client, MANAGESIEVE_CMD_REPLY_BYE, text)

#define client_send_okresp(client, resp_code, text) \
	client_send_reply_code(client, MANAGESIEVE_CMD_REPLY_OK, \
			       resp_code, text)
#define client_send_noresp(client, resp_code, text) \
	client_send_reply_code(client, MANAGESIEVE_CMD_REPLY_NO, \
			       resp_code, text)
#define client_send_byeresp(client, resp_code, text) \
	client_send_reply_code(client, MANAGESIEVE_CMD_REPLY_BYE, \
			       resp_code, text)

#endif
