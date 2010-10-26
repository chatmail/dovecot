/* Copyright (c) 2009-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "base64.h"
#include "str.h"
#include "auth-client.h"
#include "auth-server-connection.h"
#include "auth-master.h"

#include <stdio.h>
#include <unistd.h>

struct authtest_input {
	const char *username;
	const char *service;
	const char *password;
};

static const char *auth_socket_path = NULL;

static int authtest_userdb(const struct authtest_input *input)
{
	struct auth_master_connection *conn;
	pool_t pool;
	struct auth_user_reply reply;
	const char *const *fields;
	unsigned int i, count;
	int ret;

	if (auth_socket_path == NULL)
		auth_socket_path = PKG_RUNDIR"/auth-master";

	pool = pool_alloconly_create("auth master lookup", 1024);

	conn = auth_master_init(auth_socket_path, FALSE);
	ret = auth_master_user_lookup(conn, input->username, input->service,
				      pool, &reply);
	if (ret < 0)
		i_fatal("userdb lookup failed");
	else if (ret == 0) {
		printf("userdb lookup: user %s doesn't exist\n",
		       input->username);
	} else {
		printf("userdb: %s\n", input->username);

		if (reply.uid != (uid_t)-1)
			printf("uid   : %s\n", dec2str(reply.uid));
		if (reply.gid != (gid_t)-1)
			printf("gid   : %s\n", dec2str(reply.gid));
		if (reply.user != NULL)
			printf("user  : %s\n", reply.user);
		if (reply.home != NULL)
			printf("home  : %s\n", reply.home);
		if (reply.chroot != NULL)
			printf("chroot: %s\n", reply.chroot);
		fields = array_get(&reply.extra_fields, &count);
		if (count > 0) {
			printf("extra fields:\n");
			for (i = 0; i < count; i++)
				printf("  %s\n", fields[i]);
		}
	}
	auth_master_deinit(&conn);
	return ret == 0 ? 1 : 0;
}

static void auth_callback(struct auth_request *request ATTR_UNUSED, int status,
			  const char *data_base64 ATTR_UNUSED,
			  const char *const *args, void *context)
{
	const struct authtest_input *input = context;

	if (!io_loop_is_running(current_ioloop))
		return;

	if (status == 0)
		i_fatal("passdb expects SASL continuation");

	if (status < 0)
		printf("passdb: %s auth failed\n", input->username);
	else
		printf("passdb: %s auth succeeded\n", input->username);

	if (*args != NULL) {
		printf("extra fields:\n");
		for (; *args != NULL; args++)
			printf("  %s\n", *args);
	}
	io_loop_stop(current_ioloop);
}

static void auth_connected(struct auth_client *client,
			   bool connected, void *context)
{
	struct authtest_input *input = context;
	struct auth_request *request;
	struct auth_request_info info;
	string_t *init_resp, *base64_resp;
	const char *error;

	if (!connected)
		i_fatal("Couldn't connect to auth socket");

	init_resp = t_str_new(128);
	str_append_c(init_resp, '\0');
	str_append(init_resp, input->username);
	str_append_c(init_resp, '\0');
	str_append(init_resp, input->password);

	base64_resp = t_str_new(128);
	base64_encode(str_data(init_resp), str_len(init_resp), base64_resp);

	memset(&info, 0, sizeof(info));
	info.mech = "PLAIN";
	info.service = input->service;
	info.initial_resp_base64 = str_c(base64_resp);

	request = auth_client_request_new(client, NULL, &info,
					  auth_callback, input, &error);
	if (request == NULL)
		i_fatal("passdb lookup failed: %s", error);
}

static int
authtest_passdb(struct authtest_input *input)
{
	struct auth_client *client;
	struct auth_server_connection *conn;

	if (auth_socket_path == NULL)
		auth_socket_path = PKG_RUNDIR"/auth-client";

	client = auth_client_new(getpid());
	auth_client_set_connect_notify(client, auth_connected, input);
	conn = auth_server_connection_new(client, auth_socket_path);

	io_loop_run(current_ioloop);

	auth_client_set_connect_notify(client, NULL, NULL);
	auth_server_connection_destroy(&conn, FALSE);
	auth_client_free(&client);
	return 0;
}

static void usage(void)
{
	i_fatal(
"usage: authtest [-a <auth socket path>] [-s <service>] <user> [<password]");
}

int main(int argc, char *argv[])
{
	struct ioloop *ioloop;
	struct authtest_input input;
	int c, ret;

	lib_init();
	ioloop = io_loop_create();

	memset(&input, 0, sizeof(input));
	input.service = "authtest";
	while ((c = getopt(argc, argv, "a:s:")) > 0) {
		switch (c) {
		case 'a':
			auth_socket_path = optarg;
			break;
		case 's':
			input.service = optarg;
			break;
		default:
			usage();
		}
	}
	if (argv[optind] == NULL)
		usage();
	input.username = argv[optind++];

	if (argv[optind] == NULL)
		ret = authtest_userdb(&input);
	else {
		input.password = argv[optind];
		ret = authtest_passdb(&input);
	}

	lib_deinit();
	return ret;
}
