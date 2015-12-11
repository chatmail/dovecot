/* Copyright (c) 2010-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "restrict-access.h"
#include "process-title.h"
#include "master-interface.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "auth-connection.h"
#include "doveadm-connection.h"
#include "login-connection.h"
#include "notify-connection.h"
#include "user-directory.h"
#include "director.h"
#include "director-host.h"
#include "director-connection.h"
#include "director-request.h"
#include "mail-host.h"

#include <stdio.h>
#include <unistd.h>

#define AUTH_SOCKET_PATH "auth-login"
#define AUTH_USERDB_SOCKET_PATH "auth-userdb"

enum director_socket_type {
	DIRECTOR_SOCKET_TYPE_UNKNOWN = 0,
	DIRECTOR_SOCKET_TYPE_AUTH,
	DIRECTOR_SOCKET_TYPE_USERDB,
	DIRECTOR_SOCKET_TYPE_AUTHREPLY,
	DIRECTOR_SOCKET_TYPE_RING,
	DIRECTOR_SOCKET_TYPE_DOVEADM
};

static struct director *director;
static struct notify_connection *notify_conn;
static struct timeout *to_proctitle_refresh;
static ARRAY(enum director_socket_type) listener_socket_types;

static void director_refresh_proctitle_timeout(void *context ATTR_UNUSED)
{
	static uint64_t prev_requests = 0, prev_input = 0, prev_output;
	string_t *str;

	str = t_str_new(64);
	str_printfa(str, "[%u users", user_directory_count(director->users));
	str_printfa(str, ", %lu req/s",
		    (unsigned long)(director->num_requests - prev_requests));
	str_printfa(str, ", %llu+%llu kB/s",
		    (unsigned long long)(director->ring_traffic_input - prev_input)/1024,
		    (unsigned long long)(director->ring_traffic_output - prev_output)/1024);
	str_append_c(str, ']');

	prev_requests = director->num_requests;
	prev_input = director->ring_traffic_input;
	prev_output = director->ring_traffic_output;

	process_title_set(str_c(str));
}

static enum director_socket_type
director_socket_type_get_from_name(const char *path)
{
	const char *name, *suffix;

	name = strrchr(path, '/');
	if (name == NULL)
		name = path;
	else
		name++;

	suffix = strrchr(name, '-');
	if (suffix == NULL)
		suffix = name;
	else
		suffix++;

	if (strcmp(suffix, "auth") == 0)
		return DIRECTOR_SOCKET_TYPE_AUTH;
	else if (strcmp(suffix, "userdb") == 0)
		return DIRECTOR_SOCKET_TYPE_USERDB;
	else if (strcmp(suffix, "authreply") == 0)
		return DIRECTOR_SOCKET_TYPE_AUTHREPLY;
	else if (strcmp(suffix, "ring") == 0)
		return DIRECTOR_SOCKET_TYPE_RING;
	else if (strcmp(suffix, "admin") == 0 ||
		 strcmp(suffix, "doveadm") == 0)
		return DIRECTOR_SOCKET_TYPE_DOVEADM;
	else
		return DIRECTOR_SOCKET_TYPE_UNKNOWN;
}

static enum director_socket_type
listener_get_socket_type_fallback(const struct director_settings *set,
				  int listen_fd)
{
	in_port_t local_port;

	if (net_getsockname(listen_fd, NULL, &local_port) == 0 &&
	    local_port != 0) {
		/* TCP/IP connection */
		if (local_port == set->director_doveadm_port)
			return DIRECTOR_SOCKET_TYPE_DOVEADM;
		else
			return DIRECTOR_SOCKET_TYPE_RING;
	}
	return DIRECTOR_SOCKET_TYPE_AUTH;
}

static void listener_sockets_init(const struct director_settings *set,
				  struct ip_addr *listen_ip_r,
				  in_port_t *listen_port_r)
{
	const char *name;
	unsigned int i, socket_count;
	struct ip_addr ip;
	in_port_t port;
	enum director_socket_type type;

	*listen_port_r = 0;

	i_array_init(&listener_socket_types, 8);
	socket_count = master_service_get_socket_count(master_service);
	for (i = 0; i < socket_count; i++) {
		int listen_fd = MASTER_LISTEN_FD_FIRST + i;

		name = master_service_get_socket_name(master_service, listen_fd);
		type = director_socket_type_get_from_name(name);
		if (type == DIRECTOR_SOCKET_TYPE_UNKNOWN) {
			/* mainly for backwards compatibility */
			type = listener_get_socket_type_fallback(set, listen_fd);
		}
		if (type == DIRECTOR_SOCKET_TYPE_RING && *listen_port_r == 0 &&
		    net_getsockname(listen_fd, &ip, &port) == 0 && port > 0) {
			*listen_ip_r = ip;
			*listen_port_r = port;
		}
		array_idx_set(&listener_socket_types, listen_fd, &type);
	}
}

static int director_client_connected(int fd, const struct ip_addr *ip)
{
	struct director_host *host;

	host = director_host_lookup_ip(director, ip);
	if (host == NULL || host->removed) {
		i_warning("Connection from %s: Server not listed in "
			  "director_servers, dropping", net_ip2addr(ip));
		return -1;
	}

	(void)director_connection_init_in(director, fd, ip);
	return 0;
}

static void client_connected(struct master_service_connection *conn)
{
	struct auth_connection *auth;
	const char *socket_path;
	const enum director_socket_type *typep;
	bool userdb;

	if (conn->fifo) {
		if (notify_conn != NULL) {
			i_error("Received another proxy-notify connection");
			return;
		}
		master_service_client_connection_accept(conn);
		notify_conn = notify_connection_init(director, conn->fd);
		return;
	}

	typep = array_idx(&listener_socket_types, conn->listen_fd);
	switch (*typep) {
	case DIRECTOR_SOCKET_TYPE_UNKNOWN:
		i_unreached();
	case DIRECTOR_SOCKET_TYPE_AUTH:
	case DIRECTOR_SOCKET_TYPE_USERDB:
		/* a) userdb connection, probably for lmtp proxy
		   b) login connection
		   Both of them are handled exactly the same, except for which
		   auth socket they connect to. */
		userdb = *typep == DIRECTOR_SOCKET_TYPE_USERDB;
		socket_path = userdb ? AUTH_USERDB_SOCKET_PATH :
			AUTH_SOCKET_PATH;
		auth = auth_connection_init(socket_path);
		if (auth_connection_connect(auth) < 0) {
			auth_connection_deinit(&auth);
			break;
		}
		master_service_client_connection_accept(conn);
		(void)login_connection_init(director, conn->fd, auth,
			userdb ? LOGIN_CONNECTION_TYPE_USERDB :
			LOGIN_CONNECTION_TYPE_AUTH);
		break;
	case DIRECTOR_SOCKET_TYPE_AUTHREPLY:
		master_service_client_connection_accept(conn);
		(void)login_connection_init(director, conn->fd, NULL,
			LOGIN_CONNECTION_TYPE_AUTHREPLY);
		break;
	case DIRECTOR_SOCKET_TYPE_RING:
		if (director_client_connected(conn->fd, &conn->remote_ip) == 0)
			master_service_client_connection_accept(conn);
		break;
	case DIRECTOR_SOCKET_TYPE_DOVEADM:
		master_service_client_connection_accept(conn);
		(void)doveadm_connection_init(director, conn->fd);
		break;
	}
}

static void director_state_changed(struct director *dir)
{
	struct director_request *const *requestp;
	ARRAY(struct director_request *) new_requests;
	bool ret;

	if (!dir->ring_synced || !mail_hosts_have_usable(dir->mail_hosts))
		return;

	/* if there are any pending client requests, finish them now */
	t_array_init(&new_requests, 8);
	array_foreach(&dir->pending_requests, requestp) {
		ret = director_request_continue(*requestp);
		if (!ret) {
			/* a) request for a user being killed
			   b) user is weak */
			array_append(&new_requests, requestp, 1);
		}
	}
	array_clear(&dir->pending_requests);
	array_append_array(&dir->pending_requests, &new_requests);

	if (dir->to_request != NULL && array_count(&new_requests) == 0)
		timeout_remove(&dir->to_request);
}

static void main_preinit(void)
{
	const struct director_settings *set;
	struct ip_addr listen_ip;
	in_port_t listen_port;

	if (master_service_settings_get(master_service)->verbose_proctitle) {
		to_proctitle_refresh =
			timeout_add(1000, director_refresh_proctitle_timeout,
				    (void *)NULL);
	}
	set = master_service_settings_get_others(master_service)[0];

	listener_sockets_init(set, &listen_ip, &listen_port);
	if (listen_port == 0 && *set->director_servers != '\0') {
		i_fatal("No inet_listeners defined for director service "
			"(for standalone keep director_servers empty)");
	}

	director = director_init(set, &listen_ip, listen_port,
				 director_state_changed);
	director_host_add_from_string(director, set->director_servers);
	director_find_self(director);
	if (mail_hosts_parse_and_add(director->mail_hosts,
				     set->director_mail_servers) < 0)
		i_fatal("Invalid value for director_mail_servers setting");
	director->orig_config_hosts = mail_hosts_dup(director->mail_hosts);

	restrict_access_by_env(NULL, FALSE);
	restrict_access_allow_coredumps(TRUE);
}

static void main_deinit(void)
{
	if (to_proctitle_refresh != NULL)
		timeout_remove(&to_proctitle_refresh);
	if (notify_conn != NULL)
		notify_connection_deinit(&notify_conn);
	director_deinit(&director);
	doveadm_connections_deinit();
	login_connections_deinit();
	auth_connections_deinit();
	array_free(&listener_socket_types);
}

int main(int argc, char *argv[])
{
	const struct setting_parser_info *set_roots[] = {
		&director_setting_parser_info,
		NULL
	};
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_NO_IDLE_DIE;
	in_port_t test_port = 0;
	const char *error;
	bool debug = FALSE;
	int c;

	master_service = master_service_init("director", service_flags,
					     &argc, &argv, "Dt:");
	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'D':
			debug = TRUE;
			break;
		case 't':
			if (net_str2port(optarg, &test_port) < 0)
				i_fatal("-t: Not a port number: %s", optarg);
			break;
		default:
			return FATAL_DEFAULT;
		}
	}
	if (master_service_settings_read_simple(master_service, set_roots,
						&error) < 0)
		i_fatal("Error reading configuration: %s", error);

	master_service_init_log(master_service, "director: ");

	main_preinit();
	director->test_port = test_port;
	director_debug = debug;
	director_connect(director);

	if (director->test_port != 0) {
		/* we're testing, possibly writing to same log file.
		   make it clear which director we are. */
		master_service_init_log(master_service,
			t_strdup_printf("director(%s): ",
					net_ip2addr(&director->self_ip)));
	}
	master_service_init_finish(master_service);

	master_service_run(master_service, client_connected);
	main_deinit();

	master_service_deinit(&master_service);
        return 0;
}
