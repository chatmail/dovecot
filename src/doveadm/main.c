/* Copyright (c) 2005-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "restrict-access.h"
#include "process-title.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "settings-parser.h"
#include "dict.h"
#include "client-connection.h"
#include "client-connection-private.h"
#include "doveadm-settings.h"
#include "doveadm-dump.h"
#include "doveadm-mail.h"
#include "doveadm-print-private.h"
#include "doveadm-server.h"
#include "ostream.h"

const struct doveadm_print_vfuncs *doveadm_print_vfuncs_all[] = {
	&doveadm_print_server_vfuncs,
	&doveadm_print_json_vfuncs,
	NULL
};

struct client_connection *doveadm_client;
bool doveadm_verbose_proctitle;
int doveadm_exit_code = 0;

static void doveadm_die(void)
{
	/* do nothing. doveadm connections should be over soon. */
}

static void client_connected(struct master_service_connection *conn)
{
	if (doveadm_client != NULL) {
		i_error("doveadm server can handle only a single client");
		return;
	}

	master_service_client_connection_accept(conn);
	if (strcmp(conn->name, "http") == 0) {
		doveadm_client = client_connection_create_http(conn->fd, conn->ssl);
	} else {
		doveadm_client = client_connection_create(conn->fd, conn->listen_fd,
							  conn->ssl);
	}
}

void help(const struct doveadm_cmd *cmd)
{
	i_fatal("Client sent invalid command. Usage: %s %s",
		cmd->name, cmd->short_usage);
}

void help_ver2(const struct doveadm_cmd_ver2 *cmd)
{
	i_fatal("Client sent invalid command. Usage: %s %s",
		cmd->name, cmd->usage);
}

static void main_preinit(void)
{
	restrict_access_by_env(NULL, FALSE);
	restrict_access_allow_coredumps(TRUE);
}

static void main_init(void)
{
	doveadm_server = TRUE;
	doveadm_settings = master_service_settings_get_others(master_service)[0];
	doveadm_settings = settings_dup(&doveadm_setting_parser_info,
					doveadm_settings,
					pool_datastack_create());
	doveadm_verbose_proctitle =
		master_service_settings_get(master_service)->verbose_proctitle;
	if (doveadm_verbose_proctitle)
		process_title_set("[idling]");

	doveadm_http_server_init();
	doveadm_cmds_init();
	doveadm_register_auth_server_commands();
	doveadm_dump_init();
	doveadm_mail_init();
	dict_drivers_register_builtin();
	doveadm_load_modules();
}

static void main_deinit(void)
{
	if (doveadm_client != NULL)
		client_connection_destroy(&doveadm_client);
	doveadm_mail_deinit();
	doveadm_dump_deinit();
	doveadm_unload_modules();
	dict_drivers_unregister_builtin();
	doveadm_print_deinit();
	doveadm_cmds_deinit();
	doveadm_http_server_deinit();
}

int main(int argc, char *argv[])
{
	const struct setting_parser_info *set_roots[] = {
		&doveadm_setting_parser_info,
		NULL
	};
	enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_KEEP_CONFIG_OPEN;
	struct master_service_settings_input input;
	struct master_service_settings_output output;
	const char *error;
	int c;

	master_service = master_service_init("doveadm", service_flags,
					     &argc, &argv, "D");
	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'D':
			doveadm_debug = TRUE;
			doveadm_verbose = TRUE;
			break;
		default:
			return FATAL_DEFAULT;
		}
	}

	i_zero(&input);
	input.roots = set_roots;
	input.module = "doveadm";
	input.service = "doveadm";

	if (master_service_settings_read(master_service, &input, &output,
					 &error) < 0)
		i_fatal("Error reading configuration: %s", error);

	master_service_init_log(master_service, "doveadm: ");
	main_preinit();
	master_service_set_die_callback(master_service, doveadm_die);

	main_init();
	master_service_init_finish(master_service);
	master_service_run(master_service, client_connected);

	main_deinit();
	master_service_deinit(&master_service);
        return 0;
}
