#include "common.h"
#include "base64.h"
#include "buffer.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "safe-memset.h"
#include "str.h"
#include "str-sanitize.h"

#include "managesieve-parser.h"
#include "managesieve-quote.h"
#include "auth-client.h"
#include "client.h"
#include "client-authenticate.h"
#include "managesieve-proxy.h"

#include <unistd.h>
#include <stdlib.h>

#define MANAGESIEVE_SERVICE_NAME "managesieve"

/* FIXME: The use of the ANONYMOUS mechanism is currently denied 
 */
static bool _sasl_mechanism_acceptable
	(const struct auth_mech_desc *mech, bool secured) {

	/* a) transport is secured
	   b) auth mechanism isn't plaintext
       c) we allow insecure authentication
	 */

	if ((mech->flags & MECH_SEC_PRIVATE) == 0 &&
		(mech->flags & MECH_SEC_ANONYMOUS) == 0 &&
 		(secured || !disable_plaintext_auth ||
		(mech->flags & MECH_SEC_PLAINTEXT) == 0)) {
    		return 1;     
	}  

	return 0;
}

const char *client_authenticate_get_capabilities(bool secured)
{
	const struct auth_mech_desc *mech;
	unsigned int i, count;
	string_t *str;

	str = t_str_new(128);
	mech = auth_client_get_available_mechs(auth_client, &count);

	if ( count > 0 ) {
		if ( _sasl_mechanism_acceptable(&(mech[0]), secured) ) {
			str_append(str, mech[0].name);
		}
     
		for (i = 1; i < count; i++) {
			if ( _sasl_mechanism_acceptable(&(mech[i]), secured) ) {
				str_append_c(str, ' ');
				str_append(str, mech[i].name);
			}
		}
	}

	return str_c(str);
}

static void client_auth_input(struct managesieve_client *client)
{
	struct managesieve_arg *args;
	const char *msg;
	char *line;
	bool fatal;

	if (client->destroyed)
		return;

	if (!client_read(client))
		return;

	if (client->skip_line) {
		if (i_stream_next_line(client->input) == NULL)
			return;

		client->skip_line = FALSE;
	}

	switch (managesieve_parser_read_args(client->parser, 0, 0, &args)) {
	case -1:
		/* error */
		msg = managesieve_parser_get_error(client->parser, &fatal);
		if (fatal) {
			/* FIXME: What to do? */
		}
	  
		sasl_server_auth_client_error(&client->common, msg);
		return;
	case -2:
		/* not enough data */
		return;
	}

	if (args[0].type != MANAGESIEVE_ARG_STRING || 
		args[1].type != MANAGESIEVE_ARG_EOL) {
		sasl_server_auth_client_error(&client->common, "Invalid AUTHENTICATE client response.");
		return;
	}

	line = MANAGESIEVE_ARG_STR(&args[0]);

    auth_client_request_continue(client->common.auth_request, line);
	io_remove(&client->io);

	/* clear sensitive data */
	safe_memset(line, 0, strlen(line));
}

static void client_auth_failed(struct managesieve_client *client)
{
    /* get back to normal client input. */
    if (client->io != NULL)
        io_remove(&client->io);
    client->io = io_add(client->common.fd, IO_READ,
                client_input, client);
}

static bool client_handle_args(struct managesieve_client *client,
			       const char *const *args, bool success)
{
	const char *reason = NULL, *host = NULL, *destuser = NULL, *pass = NULL;
	string_t *resp_code;
	unsigned int port = 2000;
	bool proxy = FALSE, temp = FALSE, nologin = !success, proxy_self;

	for (; *args != NULL; args++) {
		if (strcmp(*args, "nologin") == 0)
			nologin = TRUE;
		else if (strcmp(*args, "proxy") == 0)
			proxy = TRUE;
		else if (strcmp(*args, "temp") == 0)
			temp = TRUE;
		else if (strncmp(*args, "reason=", 7) == 0)
			reason = *args + 7;
		else if (strncmp(*args, "host=", 5) == 0)
			host = *args + 5;
		else if (strncmp(*args, "port=", 5) == 0)
			port = atoi(*args + 5);
		else if (strncmp(*args, "destuser=", 9) == 0)
			destuser = *args + 9;
		else if (strncmp(*args, "pass=", 5) == 0)
			pass = *args + 5;
	}

	if (destuser == NULL)
		destuser = client->common.virtual_user;

	 proxy_self = proxy &&
        login_proxy_is_ourself(&client->common, host, port, destuser);	
  	if (proxy && !proxy_self) {
		/* we want to proxy the connection to another server.
		don't do this unless authentication succeeded. with
		master user proxying we can get FAIL with proxy still set.

		proxy host=.. [port=..] [destuser=..] pass=.. */

		if (!success)
			return FALSE;
		if (managesieve_proxy_new(client, host, port, destuser, pass) < 0)
			client_destroy_internal_failure(client);
		return TRUE;
	}

	if (!proxy && host != NULL) {
		/* MANAGESIEVE referral

		   [nologin] referral host=.. [port=..] [destuser=..]
		   [reason=..]

		   NO (REFERRAL sieve://user;AUTH=mech@host:port/) Can't login.
		   OK (...) Logged in, but you should use this server instead.
		   .. [REFERRAL ..] (Reason from auth server)
		*/
		resp_code = t_str_new(128);
		str_printfa(resp_code, "REFERRAL sieve://%s;AUTH=%s@%s",
			    destuser, client->common.auth_mech_name, host);
		if (port != 2000)
			str_printfa(resp_code, ":%u", port);

		if (reason == NULL) {
			if (nologin)
				reason = "Try this server instead.";
			else 
				reason = "Logged in, but you should use "
					"this server instead.";
		}

		if (!nologin) {
			client_send_okresp(client, str_c(resp_code), reason);
			client_destroy(client, "Login with referral");
			return TRUE;
		}
		client_send_noresp(client, str_c(resp_code), reason);
	} else if (nologin || proxy_self) {
		/* Authentication went ok, but for some reason user isn't
		   allowed to log in. Shouldn't probably happen. */
		if (proxy_self) {
			client_syslog(&client->common,
				"Proxying loops to itself");
        }

		if (reason != NULL)
			client_send_no(client, reason);
		else if (temp)
			client_send_no(client, AUTH_TEMP_FAILED_MSG);		
		else
			client_send_no(client, AUTH_FAILED_MSG);
	} else {
		/* normal login/failure */
		return FALSE;
	}

	i_assert(nologin || proxy_self);

	managesieve_parser_reset(client->parser);

	if (!client->destroyed) 
		client_auth_failed(client);
	return TRUE;
}

static void sasl_callback(struct client *_client, enum sasl_server_reply reply,
			  const char *data, const char *const *args)
{
	struct managesieve_client *client = (struct managesieve_client *)_client;
	string_t *str;

	i_assert(!client->destroyed ||
		reply == SASL_SERVER_REPLY_CLIENT_ERROR ||
		reply == SASL_SERVER_REPLY_MASTER_FAILED);

	client->skip_line = TRUE;

	switch (reply) {
	case SASL_SERVER_REPLY_SUCCESS:
		timeout_remove(&client->to_auth_waiting);
		if (args != NULL) {
			if (client_handle_args(client, args, TRUE))
				break;
		}

		client_destroy(client, "Login");
		break;
	case SASL_SERVER_REPLY_AUTH_FAILED:
	case SASL_SERVER_REPLY_CLIENT_ERROR:
		timeout_remove(&client->to_auth_waiting);
		if (args != NULL) {
			if (client_handle_args(client, args, FALSE))
				break;
		}

		client_send_no(client, data != NULL ? data : AUTH_FAILED_MSG);

		managesieve_parser_reset(client->parser);

		if (!client->destroyed) 
			client_auth_failed(client);
		break;
	case SASL_SERVER_REPLY_MASTER_FAILED:
		if (data == NULL)
			client_destroy_internal_failure(client);
		else {
			client_send_no(client, data);
			client_destroy(client, data);
		}
		break;
	case SASL_SERVER_REPLY_CONTINUE:
		t_push();
		str = t_str_new(256);
		managesieve_quote_append_string(str, data, TRUE);
		str_append(str, "\r\n");
				
		/* don't check return value here. it gets tricky if we try
		   to call client_destroy() in here. */
		(void)o_stream_send(client->output, str_c(str), str_len(str));
		t_pop();

		managesieve_parser_reset(client->parser);

		i_assert(client->io == NULL);
        client->io = io_add(client->common.fd, IO_READ,
                    client_auth_input, client);
        client_auth_input(client);
		
		return;
	}

	client_unref(client);
}

int cmd_authenticate(struct managesieve_client *client, struct managesieve_arg *args)
{
	const char *mech_name, *init_resp = NULL;

	/* one mandatory argument: authentication mechanism name */
	if (args[0].type != MANAGESIEVE_ARG_STRING)
		return -1;
	if (args[1].type != MANAGESIEVE_ARG_EOL) {
		/* optional SASL initial response */
		if (args[1].type != MANAGESIEVE_ARG_STRING ||
		    args[2].type != MANAGESIEVE_ARG_EOL)
			return -1;
		init_resp = MANAGESIEVE_ARG_STR(&args[1]);
	}

	mech_name = MANAGESIEVE_ARG_STR(&args[0]);
	if (*mech_name == '\0') 
		return -1;

	/* FIXME: This refuses the ANONYMOUS mechanism. 
	 *   This can be removed once anonymous login is implemented according to the 
	 *   draft RFC. - Stephan
	 */
	if ( strncasecmp(mech_name, "ANONYMOUS", 9) == 0 ) {
		client_send_no(client, "ANONYMOUS mechanism is not implemented.");		
		return 0;
	}

    client_ref(client);
    sasl_server_auth_begin(&client->common, MANAGESIEVE_SERVICE_NAME, mech_name,
                   init_resp, sasl_callback);
    if (!client->common.authenticating)
        return 1;

    /* don't handle input until we get the initial auth reply */
    if (client->io != NULL)
        io_remove(&client->io);
    client_set_auth_waiting(client);

	managesieve_parser_reset(client->parser);

	return 0;
}

