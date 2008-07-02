/* Copyright (C) 2004 Timo Sirainen */

#include <string.h>
#include "common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "str-sanitize.h"
#include "safe-memset.h"
#include "buffer.h"
#include "base64.h"
#include "client.h"
#include "managesieve-quote.h"
#include "managesieve-proxy.h"
#include "managesieve-parser.h"

static int proxy_input_line(struct managesieve_client *client,
			    struct ostream *output, const char *line)
{
	string_t *str;
	const char *msg;

	i_assert(!client->destroyed);

	if (!client->proxy_login_sent) {
		string_t *plain_login, *base64;
		struct istream *input;
		struct managesieve_parser *parser;
 		struct managesieve_arg *args;
		int ret;
		bool fatal = FALSE, greeting_recvd = FALSE;

		/* Server will send greeting which is actually a capability 
		 * response. Output from a faulty server should not be accepted,
		 * so the response is parsed and verified.
		 */

		/* Build an input stream for the managesieve parser 
		 *  FIXME: It would be nice if the line-wise parsing could be
		 *    substituded by something similar to the command line interpreter.
		 *    However, the current login_proxy structure does not make streams
		 *    known until inside proxy_input handler.
		 */
		line = t_strconcat(line, "\r\n", NULL);
		input = i_stream_create_from_data(line, strlen(line));
		parser = managesieve_parser_create(input, NULL, MAX_MANAGESIEVE_LINE);
		managesieve_parser_reset(parser);

	    /* Parse input 
		 *  FIXME: Theoretically the OK response could include a 
		 *   response code which could be rejected by the parser. 
		 */ 
		(void)i_stream_read(input);
		ret = managesieve_parser_read_args(parser, 2, 0, &args);
		
		if ( ret >= 1 ) {
			if ( args[0].type == MANAGESIEVE_ARG_ATOM &&
        		strncasecmp(MANAGESIEVE_ARG_STR(&(args[0])), "OK", 2) == 0 ) {

				/* Received OK response; greeting is finished */
				greeting_recvd = TRUE;

      		} else if ( args[0].type == MANAGESIEVE_ARG_STRING ) {
        		if ( strncasecmp(MANAGESIEVE_ARG_STR(&(args[0])), "SASL", 4) == 0 ) {
					/* Check whether the server supports the SASL mechanism 
		    		 * we are going to use (currently only PLAIN supported). 
					 */
					if ( ret == 2 && args[1].type == MANAGESIEVE_ARG_STRING ) {
						char *p = MANAGESIEVE_ARG_STR(&(args[1]));
						int mech_found = FALSE;
								
						while ( p != NULL ) {
							if ( strncasecmp(p, "PLAIN", 5) == 0 ) {
								mech_found = TRUE;
								break;
              				}

							p = strchr(p, ' ');
							if ( p != NULL ) p++;
						}	 

						if ( !mech_found ) {
							client_syslog(&client->common, "proxy: "
			          			"Server does not support required PLAIN SASL mechanism.");

							fatal = TRUE;
						} 	
					}
				} 	
			} else {
				/* Do not accept faulty server */
        		client_syslog(&client->common, t_strdup_printf("proxy: "
          			"Remote returned with invalid capability/greeting line: %s",
          			str_sanitize(line,160)));

				fatal = TRUE;
			}

    	} else if ( ret == -2 ) {
			/* Parser needs more data (not possible on mem stream) */
			i_unreached();

    	} else if ( ret < 0 ) {
			const char *error_str = managesieve_parser_get_error(parser, &fatal);
			error_str = (error_str != NULL ? error_str : "unknown (bug)" );
	
			/* Do not accept faulty server */
			client_syslog(&client->common, t_strdup_printf("proxy: "
				"Protocol parse error(%d) in capability/greeting line: %s (line='%s')",
				ret, error_str, line));
	
			fatal = TRUE;
		}

		/* Cleanup parser */
    	managesieve_parser_destroy(&parser);
	    i_stream_destroy(&input);

		/* Time to exit if greeting was not accepted */
		if ( fatal ) {			
			client_destroy_internal_failure(client);
	
			return -1;
		}

		/* Wait until greeting is received completely */
		if ( !greeting_recvd ) return 0;

		/* Send AUTHENTICATE "PLAIN" command 
    	 *  FIXME: Currently there seems to be no SASL client implementation,
		 *    so only implement the trivial PLAIN method 
		 *    - Stephan
	     */
		t_push();
	
		/*   Base64-encode the credentials 
		 * 	   [authorization ID \0 authentication ID \0 pass]
	     */
		plain_login = buffer_create_dynamic(pool_datastack_create(), 64);
		buffer_append_c(plain_login, '\0');
		buffer_append(plain_login, client->proxy_user, strlen(client->proxy_user));
	  	buffer_append_c(plain_login, '\0');
		buffer_append(plain_login, client->proxy_password, strlen(client->proxy_password));

		base64 = buffer_create_dynamic(pool_datastack_create(),
			MAX_BASE64_ENCODED_SIZE(plain_login->used));
		base64_encode(plain_login->data, plain_login->used, base64);

		/*   Send command */
		str = t_str_new(128);
		str_append(str, "AUTHENTICATE \"PLAIN\" ");
		managesieve_quote_append_string(str, str_c(base64),  FALSE);
		str_append(str, "\r\n");
		(void)o_stream_send(output, str_data(str), str_len(str));
		
		/*   Cleanup */
		t_pop();

		/* Cleanup sensitive data */
		safe_memset(client->proxy_password, 0,
			   strlen(client->proxy_password));
		i_free(client->proxy_password);
		client->proxy_password = NULL;
		client->proxy_login_sent = TRUE;

		return 0;

	} else { 
		if (strncasecmp(line, "OK ", 3) == 0) {
			/* Login successful. Send this line to client. */
			o_stream_cork(client->output);
			(void)o_stream_send_str(client->output, line);
			(void)o_stream_send(client->output, "\r\n", 2);
			o_stream_uncork(client->output);

			msg = t_strdup_printf("proxy(%s): started proxying to %s:%u",
				      client->common.virtual_user,
				      login_proxy_get_host(client->proxy),
				      login_proxy_get_port(client->proxy));

			(void)client_skip_line(client);
			login_proxy_detach(client->proxy, client->input,
				   client->output);

			client->proxy = NULL;
			client->input = NULL;
			client->output = NULL;
			client->common.fd = -1;
			client_destroy(client, msg);

		} else {
			/* Login failed. Send our own failure reply so client can't
		  	 * figure out if user exists or not just by looking at the
			 * reply string.
			 */
			client_send_no(client, AUTH_FAILED_MSG);

			/* allow client input again */
			i_assert(client->io == NULL);
			client->io = io_add(client->common.fd, IO_READ,
				    client_input, client);

			login_proxy_free(client->proxy);
			client->proxy = NULL;

			i_free(client->proxy_user);
			client->proxy_user = NULL;
		}

		return -1;
	}

	i_unreached();
	return -1;
}

static void proxy_input(struct istream *input, struct ostream *output,
			void *context)
{
	struct managesieve_client *client = context;
	const char *line;

	if (input == NULL) {
		if (client->io != NULL) {
			/* remote authentication failed, we're just
			   freeing the proxy */
			return;
		}

		if (client->destroyed) {
			/* we came here from client_destroy() */
			return;
		}

		/* failed for some reason, probably server disconnected */
		client_send_byeresp(client, "TRYLATER", "Temporary login failure.");
		client_destroy(client, NULL);
		return;
	}

	i_assert(!client->destroyed);

	switch (i_stream_read(input)) {
	case -2:
		/* buffer full */
		client_syslog(&client->common, "proxy: Remote input buffer full");
		client_destroy_internal_failure(client);
		return;
	case -1:
		/* disconnected */
		client_destroy(client, "Proxy: Remote disconnected");
		return;
	}

	while ((line = i_stream_next_line(input)) != NULL) {
		if (proxy_input_line(client, output, line) < 0)
			break;
	}
}

int managesieve_proxy_new(struct managesieve_client *client, const char *host,
		   unsigned int port, const char *user, const char *password)
{
	i_assert(user != NULL);
	i_assert(!client->destroyed);

	if (password == NULL) {
		client_syslog(&client->common, "proxy: password not given");
		return -1;
	}

	i_assert(client->refcount > 1);
	connection_queue_add(1);

	if (client->destroyed) {
		/* connection_queue_add() decided that we were the oldest
		   connection and killed us. */
		return -1;
	}

	client->proxy = login_proxy_new(&client->common, host, port,
					proxy_input, client);
	if (client->proxy == NULL)
		return -1;

	client->proxy_login_sent = FALSE;
	client->proxy_user = i_strdup(user);
	client->proxy_password = i_strdup(password);

	/* disable input until authentication is finished */
	if (client->io != NULL)
		io_remove(&client->io);

	return 0;
}
