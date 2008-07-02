/* Copyright (c) 2006-2008 Dovecot Sieve authors, see the included AUTHORS file */

#include "common.h"
#include "buffer.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "process-title.h"
#include "safe-memset.h"
#include "str.h"
#include "strfuncs.h"
#include "strescape.h"

#include "managesieve-parser.h"
#include "managesieve-quote.h"
#include "sieve.h"

#include "client.h"
#include "client-authenticate.h"
#include "auth-client.h"
#include "ssl-proxy.h"
#include "managesieve-proxy.h"

#include <stdlib.h>

/* max. size of one parameter in line, or max reply length in SASL
   authentication */
#define MAX_INBUF_SIZE 4096

/* max. size of output buffer. if it gets full, the client is disconnected.
   SASL authentication gives the largest output. */
#define MAX_OUTBUF_SIZE 4096

/* maximum length for IMAP command line. */
#define MAX_MANAGESIEVE_LINE 8192

/* Disconnect client after idling this many milliseconds */
#define CLIENT_LOGIN_IDLE_TIMEOUT_MSECS (3*60*1000)

/* Disconnect client when it sends too many bad commands */
#define CLIENT_MAX_BAD_COMMANDS 10

/* When max. number of simultaneous connections is reached, few of the
   oldest connections are disconnected. Since we have to go through all of the
   clients, it's faster if we disconnect multiple clients. */
#define CLIENT_DESTROY_OLDEST_COUNT 16

/* If we've been waiting auth server to respond for over this many milliseconds,
   send a "waiting" message. */
#define AUTH_WAITING_TIMEOUT_MSECS (30*1000)

#if CLIENT_LOGIN_IDLE_TIMEOUT_MSECS >= AUTH_REQUEST_TIMEOUT*1000
#  error client idle timeout must be smaller than authentication timeout
#endif

const char *login_protocol = "MANAGESIEVE";
const char *capability_string = CAPABILITY_STRING;

const char *managesieve_implementation_string;

static void client_set_title(struct managesieve_client *client)
{
	const char *addr;

	if (!verbose_proctitle || !process_per_connection)
		return;

	addr = net_ip2addr(&client->common.ip);
	if (addr == NULL)
		addr = "??";

	process_title_set(t_strdup_printf(client->common.tls ?
					  "[%s TLS]" : "[%s]", addr));
}

static void client_open_streams(struct managesieve_client *client, int fd)
{
	client->input = i_stream_create_fd(fd, MAX_INBUF_SIZE, FALSE);
	client->output = o_stream_create_fd(fd, MAX_OUTBUF_SIZE, FALSE);
	client->parser = managesieve_parser_create(client->input, client->output,
					    MAX_MANAGESIEVE_LINE);
}

/* Skip incoming data until newline is found,
   returns TRUE if newline was found. */
bool client_skip_line(struct managesieve_client *client)
{
	const unsigned char *data;
	size_t i, data_size;

	data = i_stream_get_data(client->input, &data_size);

	for (i = 0; i < data_size; i++) {
		if (data[i] == '\n') {
			i_stream_skip(client->input, i+1);
			return TRUE;
		}
	}

	return FALSE;
}

static void client_send_capabilities(struct managesieve_client *client)
{
	const char *auths;
	const char *sievecap, *sieveimpl;

	sievecap = sieve_get_capabilities();
	if (sievecap == NULL)
	  	sievecap = "";

	t_push();
	sievecap = t_strconcat("\"SIEVE\" \"", sievecap, "\"", NULL);
	sieveimpl = t_strconcat("\"IMPLEMENTATION\" \"",
    managesieve_implementation_string, "\"", NULL);

	auths = client_authenticate_get_capabilities(client->common.secured);

	/* We assume no MANAGESIEVE-string incompatible values are produced here */
	client_send_line(client, sieveimpl);
	client_send_line(client, t_strconcat("\"SASL\" \"", auths, "\"", NULL) );
	client_send_line(client, sievecap);

	if (ssl_initialized && !client->common.tls)
		client_send_line(client, "\"STARTTLS\"" );

	t_pop();
}

static int cmd_capability(struct managesieve_client *client)
{
	client_send_capabilities(client);
	client_send_ok(client, "Capability completed.");
	return TRUE;
}

static void client_start_tls(struct managesieve_client *client)
{
	int fd_ssl;

    client_ref(client);
    connection_queue_add(1);
    if (!client_unref(client) || client->destroyed)
        return;

	fd_ssl = ssl_proxy_new(client->common.fd, &client->common.ip,
			       &client->common.proxy);
	if (fd_ssl == -1) {
		client_send_bye(client, "TLS initialization failed.");
		client_destroy(client, "Disconnected: TLS initialization failed.");
		return;
	}

	client->common.tls = TRUE;
	client->common.secured = TRUE;
	client_set_title(client);

	client->common.fd = fd_ssl;
	i_stream_unref(&client->input);
	o_stream_unref(&client->output);
	managesieve_parser_destroy(&client->parser);

	/* CRLF is lost from buffer when streams are reopened. */
	client->skip_line = FALSE;

	client_open_streams(client, fd_ssl);
	client->io = io_add(client->common.fd, IO_READ, client_input, client);
}

static int client_output_starttls(void *context)
{
	struct managesieve_client *client = context;
	int ret;

	if ((ret = o_stream_flush(client->output)) < 0) {
		client_destroy(client, "Disconnected");
		return 1;
	}

	if (ret > 0) {
		o_stream_unset_flush_callback(client->output);
		client_start_tls(client);
	}
	return 1;
}

static int cmd_starttls(struct managesieve_client *client)
{
	if (client->common.tls) {
		client_send_no(client, "TLS is already active.");
		return 1;
	}

	if (!ssl_initialized) {
		client_send_no(client, "TLS support isn't enabled.");
		return 1;
	}

	/* remove input handler, SSL proxy gives us a new fd. we also have to
	   remove it in case we have to wait for buffer to be flushed */
	if (client->io != NULL)
		io_remove(&client->io);

	client_send_ok(client, "Begin TLS negotiation now.");

	/* uncork the old fd */
	o_stream_uncork(client->output);

	if (o_stream_flush(client->output) <= 0) {
		/* the buffer has to be flushed */
		o_stream_set_flush_pending(client->output, TRUE);
		o_stream_set_flush_callback(client->output,
					    client_output_starttls, client);
	} else {
		client_start_tls(client);
	}

    /* Cork the stream to send the capability data as a single tcp frame
     *   Some naive clients break if we don't.
     */
    o_stream_cork(client->output);

	client_send_capabilities(client);
	client_send_ok(client, "TLS negotiation successful.");

    o_stream_uncork(client->output);

	return 1;
}

static int cmd_logout(struct managesieve_client *client)
{
	client_send_ok(client, "Logout completed.");
	if (client->common.auth_tried_disabled_plaintext) {
		client_destroy(client, "Aborted login "
			"(tried to use disabled plaintext authentication)");
	} else {
		client_destroy(client, t_strdup_printf(
			"Aborted login (%u authentication attempts)",
			client->common.auth_attempts));
	}
	return 1;
}

static int client_command_execute(struct managesieve_client *client, const char *cmd,
				  struct managesieve_arg *args)
{
	cmd = t_str_ucase(cmd);
	if (strcmp(cmd, "AUTHENTICATE") == 0)
		return cmd_authenticate(client, args);
	if (strcmp(cmd, "CAPABILITY") == 0)
		return cmd_capability(client);
	if (strcmp(cmd, "STARTTLS") == 0)
		return cmd_starttls(client);
	if (strcmp(cmd, "LOGOUT") == 0)
		return cmd_logout(client);

	return -1;
}

static bool client_handle_input(struct managesieve_client *client)
{
	struct managesieve_arg *args;
	const char *msg;
	int ret;
	bool fatal;

	i_assert(!client->common.authenticating);

	if (client->cmd_finished) {
		/* clear the previous command from memory. don't do this
		   immediately after handling command since we need the
		   cmd_tag to stay some time after authentication commands. */
		client->cmd_name = NULL;
		managesieve_parser_reset(client->parser);

		/* remove \r\n */
		if (client->skip_line) {
			if (!client_skip_line(client))
				return FALSE;
			client->skip_line = FALSE;
		}

		client->cmd_finished = FALSE;
	}

	if (client->cmd_name == NULL) {
		client->cmd_name = managesieve_parser_read_word(client->parser);
		if (client->cmd_name == NULL)
			return FALSE; /* need more data */
	}

	switch (managesieve_parser_read_args(client->parser, 0, 0, &args)) {
	case -1:
		/* error */
		msg = managesieve_parser_get_error(client->parser, &fatal);
		if (fatal) {
			client_send_bye(client, msg);
			client_destroy(client, t_strconcat("Disconnected: ",
				msg, NULL));
			return FALSE;
		}

		client_send_no(client, msg);
		client->cmd_finished = TRUE;
		client->skip_line = TRUE;
		return TRUE;
	case -2:
		/* not enough data */
		return FALSE;
	}
	client->skip_line = TRUE;

	ret = client_command_execute(client, client->cmd_name, args);

	client->cmd_finished = TRUE;
	if (ret < 0) {
		if (++client->bad_counter >= CLIENT_MAX_BAD_COMMANDS) {
			client_send_bye(client,	
				"Too many invalid MANAGESIEVE commands.");
			client_destroy(client, "Disconnected: "
				"Too many invalid commands.");
			return FALSE;
		}  
		client_send_no(client,
			"Error in MANAGESIEVE command received by server.");
	}

	return ret != 0;
}

bool client_read(struct managesieve_client *client)
{
	switch (i_stream_read(client->input)) {
	case -2:
		/* buffer full */
		client_send_bye(client, "Input buffer full, aborting");
		client_destroy(client, "Disconnected: Input buffer full");
		return FALSE;
	case -1:
		/* disconnected */
		client_destroy(client, "Disconnected");
		return FALSE;
	default:
		/* something was read */
		return TRUE;
	}
}

void client_input(struct managesieve_client *client)
{
	timeout_reset(client->to_idle_disconnect);

	if (!client_read(client))
		return;

	client_ref(client);

	if (!auth_client_is_connected(auth_client)) {
		/* we're not yet connected to auth process -
		   don't allow any commands */
		/* FIXME: Can't do this with managesieve. Any other ways?
		client_send_ok(client, AUTH_WAITING_MSG);
		*/
        if (client->to_auth_waiting != NULL)
            timeout_remove(&client->to_auth_waiting);

		client->input_blocked = TRUE;
	} else {
		o_stream_cork(client->output);
		while (client_handle_input(client)) ;
		o_stream_uncork(client->output);
	}

	client_unref(client);
}

void client_destroy_oldest(void)
{
	struct client *client;
	struct managesieve_client *destroy_buf[CLIENT_DESTROY_OLDEST_COUNT];
	int i, destroy_count;

	/* find the oldest clients and put them to destroy-buffer */
	memset(destroy_buf, 0, sizeof(destroy_buf));

 	destroy_count = max_connections > CLIENT_DESTROY_OLDEST_COUNT*2 ?
        CLIENT_DESTROY_OLDEST_COUNT : I_MIN(max_connections/2, 1);
	for (client = clients; client != NULL; client = client->next) {
        struct managesieve_client *msieve_client = 
			(struct managesieve_client *) client;

        for (i = 0; i < destroy_count; i++) {
            if (destroy_buf[i] == NULL ||
                destroy_buf[i]->created > msieve_client->created) {
                /* @UNSAFE */
                memmove(destroy_buf+i+1, destroy_buf+i,
                    sizeof(destroy_buf) -
                    (i+1) * sizeof(struct managesieve_client *));
                destroy_buf[i] = msieve_client;
                break;
            }
        }
    }

    /* then kill them */
    for (i = 0; i < destroy_count; i++) {
        if (destroy_buf[i] == NULL)
            break;

        client_destroy(destroy_buf[i],
                   "Disconnected: Connection queue full");
    }
}

static void client_send_greeting(struct managesieve_client *client)
{
	/* Cork the stream to send the capability data as a single tcp frame
     *   Some naive clients break if we don't.
     */
    o_stream_cork(client->output);

  	/* Send initial capabilities */   
  	client_send_capabilities(client);
	client_send_ok(client, greeting);
	client->greeting_sent = TRUE;

    o_stream_uncork(client->output);
}

static void client_idle_disconnect_timeout(struct managesieve_client *client)
{
	/* FIXME: is this protocol compliant? */
	client_send_bye(client, "Disconnected for inactivity.");
	client_destroy(client, "Disconnected: Inactivity");
}

static void client_auth_waiting_timeout(struct managesieve_client *client)
{
	/*client_send_line(client, AUTH_WAITING_MSG);*/
	timeout_remove(&client->to_auth_waiting);
}

void client_set_auth_waiting(struct managesieve_client *client)
{
	i_assert(client->to_auth_waiting == NULL);
	client->to_auth_waiting =
		timeout_add(AUTH_WAITING_TIMEOUT_MSECS,
			client_auth_waiting_timeout, client);
}

struct client *client_create(int fd, bool ssl, const struct ip_addr *local_ip,
			     const struct ip_addr *ip)
{
	struct managesieve_client *client;

	i_assert(fd != -1);

	connection_queue_add(1);

	/* always use nonblocking I/O */
	net_set_nonblock(fd, TRUE);

	client = i_new(struct managesieve_client, 1);
	client->created = ioloop_time;
	client->refcount = 1;
	client->common.tls = ssl;
	client->common.secured = ssl || net_ip_compare(ip, local_ip);

	client->common.local_ip = *local_ip;
	client->common.ip = *ip;
	client->common.fd = fd;

	client_open_streams(client, fd);
	client->io = io_add(fd, IO_READ, client_input, client);

	client_link(&client->common);

	main_ref();

	if (!greeting_capability || auth_client_is_connected(auth_client))
		client_send_greeting(client);
	else
		client_set_auth_waiting(client);
	client_set_title(client);

	client->to_idle_disconnect =
		timeout_add(CLIENT_LOGIN_IDLE_TIMEOUT_MSECS,
			client_idle_disconnect_timeout, client);
	return &client->common;
}

void client_destroy(struct managesieve_client *client, const char *reason)
{
	if (client->destroyed)
		return;
	client->destroyed = TRUE;

	if (reason != NULL)
		client_syslog(&client->common, reason);

	client_unlink(&client->common);

	if (client->input != NULL)
		i_stream_close(client->input);
	if (client->output != NULL)
		o_stream_close(client->output);

	if (client->common.master_tag != 0)
        master_request_abort(&client->common);

    if (client->common.auth_request != NULL) {
        i_assert(client->common.authenticating);
        sasl_server_auth_client_error(&client->common, NULL);
    } else {
        i_assert(!client->common.authenticating);
    }

	if (client->io != NULL)
		io_remove(&client->io);
	if (client->to_idle_disconnect != NULL)
		timeout_remove(&client->to_idle_disconnect);
	if (client->to_auth_waiting != NULL)
		timeout_remove(&client->to_auth_waiting);

	if (client->common.fd != -1) {
		net_disconnect(client->common.fd);
		client->common.fd = -1;
	}

	if (client->proxy_password != NULL) {
        safe_memset(client->proxy_password, 0,
                strlen(client->proxy_password));
        i_free(client->proxy_password);
        client->proxy_password = NULL;
    }

    i_free(client->proxy_user);
    client->proxy_user = NULL;

    if (client->proxy != NULL) {
        login_proxy_free(client->proxy);
        client->proxy = NULL;
    }

    if (client->common.proxy != NULL) {
        ssl_proxy_free(client->common.proxy);
        client->common.proxy = NULL;
    }

    client_unref(client);

    main_listen_start();
    main_unref();
}

void client_destroy_internal_failure(struct managesieve_client *client)
{
	client_send_byeresp(client, "TRYLATER", "Internal login failure. "
		"Refer to server log for more information.");
	client_destroy(client, "Internal login failure");
}

void client_ref(struct managesieve_client *client)
{
	client->refcount++;
}

bool client_unref(struct managesieve_client *client)
{
	i_assert(client->refcount > 0);
	if (--client->refcount > 0)
		return TRUE;

	i_assert(client->destroyed);

	managesieve_parser_destroy(&client->parser);

	if (client->input != NULL)
		i_stream_unref(&client->input);
	if (client->output != NULL)
		o_stream_unref(&client->output);

	i_free(client->common.virtual_user);
	i_free(client->common.auth_mech_name);
	i_free(client);

	return FALSE;
}

void client_send_line(struct managesieve_client *client, const char *line)
{
	struct const_iovec iov[2];
	ssize_t ret;

	iov[0].iov_base = line;
	iov[0].iov_len = strlen(line);
	iov[1].iov_base = "\r\n";
	iov[1].iov_len = 2;

	ret = o_stream_sendv(client->output, iov, 2);
	if (ret < 0 || (size_t)ret != iov[0].iov_len + iov[1].iov_len) {
		/* either disconnection or buffer full. in either case we
		   want this connection destroyed. however destroying it here
		   might break things if client is still tried to be accessed
		   without being referenced.. */
		i_stream_close(client->input);
	}
}

void _client_send_response(struct managesieve_client *client, 
	const char *oknobye, const char *resp_code, const char *msg)
{
	string_t *str;

	str = t_str_new(128);
	str_append(str, oknobye);

	if ( resp_code != NULL )
	{
		str_append(str, " (");
		str_append(str, resp_code);
		str_append_c(str, ')');
	}

	if ( msg != NULL )	
	{
		str_append_c(str, ' ');
		managesieve_quote_append_string(str, msg, TRUE);
	}

	client_send_line(client, str_c(str));
}

void clients_notify_auth_connected(void)
{
	struct client *client;

	for (client = clients; client != NULL; client = client->next) {
        struct managesieve_client *msieve_client = 
			(struct managesieve_client *)client;

		if (msieve_client->to_auth_waiting != NULL)
			timeout_remove(&msieve_client->to_auth_waiting);
		if (!msieve_client->greeting_sent)
			client_send_greeting(msieve_client);
		if (msieve_client->input_blocked) {
			msieve_client->input_blocked = FALSE;
			client_input(msieve_client);
		}
	}
}

void clients_destroy_all(void)
{
	struct client *client;

	for (client = clients; client != NULL; client = client->next) {
		struct managesieve_client *msieve_client = 
			(struct managesieve_client *)client;

		client_destroy(msieve_client, "Disconnected: Shutting down");
	}
}

void clients_init(void)
{
	const char *str;

	/* Specific MANAGESIEVE settings */
	str = getenv("MANAGESIEVE_IMPLEMENTATION_STRING");
	managesieve_implementation_string = str != NULL ?
    	str : DEFAULT_MANAGESIEVE_IMPLEMENTATION_STRING;

	sieve_init("");
}

void clients_deinit(void)
{
	sieve_deinit();
}
