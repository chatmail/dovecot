/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "ostream.h"
#include "auth-client-private.h"

static void auth_server_send_new_request(struct auth_client_connection *conn,
					 struct auth_client_request *request,
					 const struct auth_request_info *info)
{
	string_t *str;

	str = t_str_new(512);
	str_printfa(str, "AUTH\t%u\t", request->id);
	str_append_tabescaped(str, info->mech);
	str_append(str, "\tservice=");
	str_append_tabescaped(str, info->service);

	event_add_str(request->event, "mechanism", info->mech);
	event_add_str(request->event, "service", info->service);

	if ((info->flags & AUTH_REQUEST_FLAG_SUPPORT_FINAL_RESP) != 0)
		str_append(str, "\tfinal-resp-ok");
	if ((info->flags & AUTH_REQUEST_FLAG_SECURED) != 0) {
		str_append(str, "\tsecured");
		if ((info->flags & AUTH_REQUEST_FLAG_TRANSPORT_SECURITY_TLS) != 0) {
			str_append(str, "=tls");
			event_add_str(request->event, "transport", "TLS");
		} else {
			event_add_str(request->event, "transport", "trusted");
		}
	} else {
		i_assert((info->flags & AUTH_REQUEST_FLAG_TRANSPORT_SECURITY_TLS) == 0);
		event_add_str(request->event, "transport", "insecure");
	}
	if ((info->flags & AUTH_REQUEST_FLAG_NO_PENALTY) != 0)
		str_append(str, "\tno-penalty");
	if ((info->flags & AUTH_REQUEST_FLAG_VALID_CLIENT_CERT) != 0)
		str_append(str, "\tvalid-client-cert");
	if ((info->flags & AUTH_REQUEST_FLAG_DEBUG) != 0)
		str_append(str, "\tdebug");

	if (info->session_id != NULL) {
		str_append(str, "\tsession=");
		str_append_tabescaped(str, info->session_id);
		event_add_str(request->event, "session", info->session_id);
	}
	if (info->cert_username != NULL) {
		str_append(str, "\tcert_username=");
		str_append_tabescaped(str, info->cert_username);
		event_add_str(request->event, "certificate_user",
			      info->cert_username);
	}
	if (info->local_ip.family != 0) {
		str_printfa(str, "\tlip=%s", net_ip2addr(&info->local_ip));
		event_add_str(request->event, "local_ip", net_ip2addr(&info->local_ip));
	}
	if (info->remote_ip.family != 0) {
		str_printfa(str, "\trip=%s", net_ip2addr(&info->remote_ip));
		event_add_str(request->event, "remote_ip", net_ip2addr(&info->remote_ip));
	}
	if (info->local_port != 0) {
		str_printfa(str, "\tlport=%u", info->local_port);
		event_add_int(request->event, "local_port", info->local_port);
	}
	if (info->remote_port != 0) {
		str_printfa(str, "\trport=%u", info->remote_port);
		event_add_int(request->event, "remote_port", info->remote_port);
	}
	if (info->real_local_ip.family != 0) {
		event_add_str(request->event, "real_local_ip",
			      net_ip2addr(&info->real_local_ip));
	}
	if (info->real_remote_ip.family != 0) {
		event_add_str(request->event, "real_remote_ip",
			      net_ip2addr(&info->real_remote_ip));
	}
	if (info->real_local_port != 0) {
		event_add_int(request->event, "real_local_port",
			      info->real_local_port);
	}
	if (info->real_remote_port != 0) {
		event_add_int(request->event, "real_remote_port",
			      info->real_remote_port);
	}
	/* send the real_* variants only when they differ from the unreal
	   ones */
	if (info->real_local_ip.family != 0 &&
	    !net_ip_compare(&info->real_local_ip, &info->local_ip)) {
		str_printfa(str, "\treal_lip=%s",
			    net_ip2addr(&info->real_local_ip));
	}
	if (info->real_remote_ip.family != 0 &&
	    !net_ip_compare(&info->real_remote_ip, &info->remote_ip)) {
		str_printfa(str, "\treal_rip=%s",
			    net_ip2addr(&info->real_remote_ip));
	}
	if (info->real_local_port != 0 &&
	    info->real_local_port != info->local_port)
		str_printfa(str, "\treal_lport=%u", info->real_local_port);
	if (info->real_remote_port != 0 &&
	    info->real_remote_port != info->remote_port)
		str_printfa(str, "\treal_rport=%u", info->real_remote_port);
	if (info->local_name != NULL &&
	    *info->local_name != '\0') {
		str_append(str, "\tlocal_name=");
		str_append_tabescaped(str, info->local_name);
		event_add_str(request->event, "local_name", info->local_name);
	}
	if (info->ssl_cipher_bits != 0 && info->ssl_cipher != NULL) {
		event_add_str(request->event, "tls_cipher", info->ssl_cipher);
		event_add_int(request->event, "tls_cipher_bits", info->ssl_cipher_bits);
		if (info->ssl_pfs != NULL) {
			event_add_str(request->event, "tls_pfs", info->ssl_pfs);
		}
	}
	if (info->ssl_protocol != NULL) {
		event_add_str(request->event, "tls_protocol", info->ssl_protocol);
	}
	if (info->client_id != NULL &&
	    *info->client_id != '\0') {
		str_append(str, "\tclient_id=");
		str_append_tabescaped(str, info->client_id);
		event_add_str(request->event, "client_id", info->client_id);
	}
	if (info->forward_fields != NULL &&
	    *info->forward_fields != '\0') {
		str_append(str, "\tforward_fields=");
		str_append_tabescaped(str, info->forward_fields);
	}
	if (array_is_created(&info->extra_fields)) {
		const char *const *fieldp;
		array_foreach(&info->extra_fields, fieldp) {
			str_append_c(str, '\t');
			str_append_tabescaped(str, *fieldp);
		}
	}
	if (info->initial_resp_base64 != NULL) {
		str_append(str, "\tresp=");
		str_append_tabescaped(str, info->initial_resp_base64);
	}
	str_append_c(str, '\n');

	struct event_passthrough *e =
		event_create_passthrough(request->event)->
		set_name("auth_client_request_started");
	e_debug(e->event(), "Started request");

	if (o_stream_send(conn->conn.output, str_data(str), str_len(str)) < 0) {
		e_error(request->event,
			"Error sending request to auth server: %m");
	}
}

struct auth_client_request *
auth_client_request_new(struct auth_client *client,
			const struct auth_request_info *request_info,
			auth_request_callback_t *callback, void *context)
{
	struct auth_client_request *request;
	pool_t pool;

	pool = pool_alloconly_create("auth client request", 512);
	request = p_new(pool, struct auth_client_request, 1);
	request->pool = pool;
	request->conn = client->conn;

	request->callback = callback;
	request->context = context;

	request->id =
		auth_client_connection_add_request(request->conn, request);
	request->created = ioloop_time;

	request->event = event_create(client->event);
	event_add_int(request->event, "id", request->id);
	event_set_append_log_prefix(request->event,
				    t_strdup_printf("request [%u]: ",
						    request->id));

	T_BEGIN {
		auth_server_send_new_request(request->conn, request, request_info);
	} T_END;
	return request;
}

void auth_client_request_continue(struct auth_client_request *request,
                                  const char *data_base64)
{
	struct const_iovec iov[3];
	const char *prefix;

	prefix = t_strdup_printf("CONT\t%u\t", request->id);

	iov[0].iov_base = prefix;
	iov[0].iov_len = strlen(prefix);
	iov[1].iov_base = data_base64;
	iov[1].iov_len = strlen(data_base64);
	iov[2].iov_base = "\n";
	iov[2].iov_len = 1;

	struct event_passthrough *e =
		event_create_passthrough(request->event)->
		set_name("auth_client_request_continued");
	e_debug(e->event(), "Continue request");

	if (o_stream_sendv(request->conn->conn.output, iov, 3) < 0) {
		e_error(request->event,
			"Error sending continue request to auth server: %m");
	}
}

static void ATTR_NULL(3, 4)
call_callback(struct auth_client_request *request,
	      enum auth_request_status status,
	      const char *data_base64,
	      const char *const *args)
{
	auth_request_callback_t *callback = request->callback;

	if (status != AUTH_REQUEST_STATUS_CONTINUE)
		request->callback = NULL;
	callback(request, status, data_base64, args, request->context);
}

static void auth_client_request_free(struct auth_client_request **_request)
{
	struct auth_client_request *request = *_request;

	*_request = NULL;

	event_unref(&request->event);
	pool_unref(&request->pool);
}

void auth_client_request_abort(struct auth_client_request **_request,
			       const char *reason)
{
	struct auth_client_request *request = *_request;

	*_request = NULL;

	struct event_passthrough *e =
		event_create_passthrough(request->event)->
		set_name("auth_client_request_finished");
	e->add_str("error", reason);
	e_debug(e->event(), "Aborted: %s", reason);

	auth_client_send_cancel(request->conn->client, request->id);
	call_callback(request, AUTH_REQUEST_STATUS_ABORT, NULL, NULL);
	/* remove the request */
	auth_client_connection_remove_request(request->conn, request->id);
	auth_client_request_free(&request);
}

unsigned int auth_client_request_get_id(struct auth_client_request *request)
{
	return request->id;
}

unsigned int
auth_client_request_get_server_pid(struct auth_client_request *request)
{
	return request->conn->server_pid;
}

const char *auth_client_request_get_cookie(struct auth_client_request *request)
{
	return request->conn->cookie;
}

bool auth_client_request_is_aborted(struct auth_client_request *request)
{
	return request->callback == NULL;
}

time_t auth_client_request_get_create_time(struct auth_client_request *request)
{
	return request->created;
}

static void args_parse_user(struct auth_client_request *request, const char *arg)
{
	if (str_begins(arg, "user="))
		event_add_str(request->event, "user", arg + 5);
	else if (str_begins(arg, "original_user="))
		event_add_str(request->event, "original_user", arg + 14);
	else if (str_begins(arg, "auth_user="))
		event_add_str(request->event, "auth_user", arg + 10);
}

void auth_client_request_server_input(struct auth_client_request *request,
				      enum auth_request_status status,
				      const char *const *args)
{
	const char *const *tmp, *base64_data = NULL;
	struct event_passthrough *e;

	if (request->callback == NULL) {
		/* aborted already */
		return;
	}

	switch (status) {
	case AUTH_REQUEST_STATUS_CONTINUE:
		e = event_create_passthrough(request->event)->
			set_name("auth_client_request_challenged");
		break;
	default:
		e = event_create_passthrough(request->event)->
			set_name("auth_client_request_finished");
		break;
	}

	for (tmp = args; *tmp != NULL; tmp++) {
		if (str_begins(*tmp, "resp=")) {
			base64_data = *tmp + 5;
		}
		args_parse_user(request, *tmp);
	}

	switch (status) {
	case AUTH_REQUEST_STATUS_OK:
		e_debug(e->event(), "Finished");
		break;
	case AUTH_REQUEST_STATUS_CONTINUE:
		base64_data = args[0];
		args = NULL;
		e_debug(e->event(), "Got challenge");
		break;
	case AUTH_REQUEST_STATUS_FAIL:
		e->add_str("error", "Authentication failed");
		e_debug(e->event(), "Finished");
		break;
	case AUTH_REQUEST_STATUS_INTERNAL_FAIL:
		e->add_str("error", "Internal failure");
		e_debug(e->event(), "Finished");
		break;
	case AUTH_REQUEST_STATUS_ABORT:
		i_unreached();
	}

	call_callback(request, status, base64_data, args);
	if (status != AUTH_REQUEST_STATUS_CONTINUE)
		auth_client_request_free(&request);
}

void auth_client_send_cancel(struct auth_client *client, unsigned int id)
{
	const char *str = t_strdup_printf("CANCEL\t%u\n", id);

	if (o_stream_send_str(client->conn->conn.output, str) < 0) {
		e_error(client->conn->conn.event,
			"Error sending request to auth server: %m");
	}
}
