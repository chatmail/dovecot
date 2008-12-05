#ifndef __CLIENT_H
#define __CLIENT_H

#include "network.h"
#include "master.h"
#include "client-common.h"

/* FIXME: Duplicate, also defined in src/managesieve */
#define DEFAULT_MANAGESIEVE_IMPLEMENTATION_STRING PACKAGE

/* maximum length for MANAGESIEVE command line. */
#define MAX_MANAGESIEVE_LINE 8192

struct managesieve_client {
	struct client common;

	time_t created;
	int refcount;

	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct managesieve_parser *parser;
	struct timeout *to_idle_disconnect, *to_auth_waiting;

	struct login_proxy *proxy;
	char *proxy_user, *proxy_password;

	unsigned int bad_counter;

	const char *cmd_name;

	unsigned int cmd_finished:1;
 	unsigned int proxy_login_sent:1;
	unsigned int skip_line:1;
	unsigned int input_blocked:1;
	unsigned int destroyed:1;
	unsigned int greeting_sent:1;
	unsigned int proxy_greeting_recvd:1;  
};

void client_destroy(struct managesieve_client *client, const char *reason);
void client_destroy_internal_failure(struct managesieve_client *client);

void client_send_line(struct managesieve_client *client, const char *line);

bool client_read(struct managesieve_client *client);
bool client_skip_line(struct managesieve_client *client);
void client_input(struct managesieve_client *client);

void client_ref(struct managesieve_client *client);
bool client_unref(struct managesieve_client *client);

void client_set_auth_waiting(struct managesieve_client *client);

void _client_send_response(struct managesieve_client *client,
  const char *oknobye, const char *resp_code, const char *msg);

#define client_send_ok(client, msg) \
	_client_send_response(client, "OK", NULL, msg)
#define client_send_no(client, msg) \
  _client_send_response(client, "NO", NULL, msg)
#define client_send_bye(client, msg) \
  _client_send_response(client, "BYE", NULL, msg)

#define client_send_okresp(client, resp_code, msg) \
  _client_send_response(client, "OK", resp_code, msg)
#define client_send_noresp(client, resp_code, msg) \
  _client_send_response(client, "NO", resp_code, msg)
#define client_send_byeresp(client, resp_code, msg) \
  _client_send_response(client, "BYE", resp_code, msg)
#endif
